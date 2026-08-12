//! Threshold cryptography (TC) bindings — peer-to-peer in-process drivers.
//!
//! Exposes four modules:
//!
//! - `confium.tc.FrostP256` — Shamir secret sharing over P-256 plus
//!   single-party ECDSA-P256 sign.
//! - `confium.tc.ElGamalP256` — threshold ElGamal KEM (encapsulate,
//!   partial_decrypt, aggregate_partials).
//! - `confium.tc.Cmp20` — CMP20 in-process DKG + threshold ECDSA sign.
//! - `confium.tc.Gg18` — GG18 in-process DKG + threshold ECDSA sign.
//!
//! CMP20 and GG18 share the same high-level shape:
//! ```python
//! kg = confium.tc.Cmp20.keygen(threshold=2, party_count=3)
//! sig = confium.tc.Cmp20.sign(kg["shares"][:2], threshold=2, message=b"hi")
//! ```

use pyo3::Bound;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use confium_tc_cmp20::inprocess as cmp20_inprocess;
use confium_tc_elgamal_p256::{
    Ciphertext as ElGamalCiphertext, DecryptionShare, PartialDecryption,
    PublicKey as ElGamalPublicKey, aggregate_partials as elgamal_aggregate,
    encapsulate as elgamal_encapsulate, partial_decrypt as elgamal_partial_decrypt,
};
use confium_tc_frost_p256::{
    Keypair, generate_keypair, public_key_for,
    scalar::{scalar_from_bytes, scalar_to_bytes},
    shamir::{Share, recover_secret, split_secret},
    sign_message,
};
use confium_tc_gg18::inprocess as gg18_inprocess;

// ===== FROST-P256 helpers =====

fn bytes_arg_to_vec(arg: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(b) = arg.extract::<Vec<u8>>() {
        return Ok(b);
    }
    if let Ok(s) = arg.extract::<&[u8]>() {
        return Ok(s.to_vec());
    }
    if let Ok(list) = arg.extract::<Vec<i64>>() {
        return list
            .into_iter()
            .map(|i| {
                if !(0..=255).contains(&i) {
                    Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "byte out of range 0..255: {i}"
                    )))
                } else {
                    Ok(i as u8)
                }
            })
            .collect();
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "expected bytes, bytearray, or list of ints",
    ))
}

fn require_scalar_32(label: &str, bytes: &[u8]) -> PyResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "{label} must be exactly 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// FROST-P256: Shamir secret sharing over P-256 plus single-party ECDSA.
#[pyclass(name = "FrostP256")]
pub struct PyFrostP256;

#[pymethods]
impl PyFrostP256 {
    /// Split a 32-byte secret scalar into `party_count` shares with
    /// threshold `threshold`. Returns a list of `(x, y_bytes)` tuples.
    #[staticmethod]
    fn split_secret<'py>(
        py: Python<'py>,
        secret: &Bound<'py, PyAny>,
        threshold: u32,
        party_count: u32,
    ) -> PyResult<Bound<'py, PyList>> {
        let bytes = bytes_arg_to_vec(secret)?;
        let arr = require_scalar_32("secret", &bytes)?;
        let scalar = scalar_from_bytes(&arr).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "secret is not a valid P-256 scalar (reduce mod n failed)",
            )
        })?;
        let shares = split_secret(&scalar, threshold, party_count);
        let list = PyList::empty_bound(py);
        for s in shares {
            let dict = PyDict::new_bound(py);
            dict.set_item("x", s.x)?;
            dict.set_item("y_bytes", PyBytes::new_bound(py, &scalar_to_bytes(&s.y)))?;
            list.append(dict)?;
        }
        Ok(list)
    }

    /// Recover the 32-byte secret scalar from a list of
    /// `{"x": int, "y_bytes": bytes}` share dicts.
    #[staticmethod]
    fn recover_secret<'py>(
        py: Python<'py>,
        shares_value: &Bound<'py, PyList>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut owned: Vec<Share> = Vec::with_capacity(shares_value.len());
        for item in shares_value.iter() {
            let d: Bound<'_, PyDict> = item.extract()?;
            let x: u32 = d.get_item("x")?.unwrap().extract()?;
            let y_value = d.get_item("y_bytes")?.unwrap();
            let y_b = bytes_arg_to_vec(&y_value)?;
            let y_arr = require_scalar_32("y_bytes", &y_b)?;
            let y = scalar_from_bytes(&y_arr).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("share y_bytes is not a valid P-256 scalar")
            })?;
            owned.push(Share { x, y });
        }
        let refs: Vec<&Share> = owned.iter().collect();
        let secret = recover_secret(&refs).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("recover_secret: {e}"))
        })?;
        Ok(PyBytes::new_bound(py, &scalar_to_bytes(&secret)))
    }

    /// Generate a fresh P-256 keypair. Returns `{"private_key": bytes,
    /// "public_key": bytes}` (32-byte scalar + 65-byte SEC1 uncompressed).
    #[staticmethod]
    fn generate_keypair<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let kp = generate_keypair();
        let d = PyDict::new_bound(py);
        d.set_item(
            "private_key",
            PyBytes::new_bound(py, &kp.to_signing_key().to_bytes()),
        )?;
        d.set_item(
            "public_key",
            PyBytes::new_bound(py, &kp.to_verifying_key().to_sec1_bytes()),
        )?;
        Ok(d)
    }

    /// Sign a message with a 32-byte P-256 private key. Returns
    /// `{"der": bytes, "fixed": bytes}` (DER-encoded + fixed-length
    /// 64-byte `(r, s)`).
    #[staticmethod]
    fn sign<'py>(
        py: Python<'py>,
        private_key: &Bound<'py, PyAny>,
        message: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let pk_b = bytes_arg_to_vec(private_key)?;
        let msg_b = bytes_arg_to_vec(message)?;
        let pk_arr = require_scalar_32("private_key", &pk_b)?;
        let secret = scalar_from_bytes(&pk_arr).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("private_key is not a valid P-256 scalar")
        })?;
        let kp = Keypair {
            secret_scalar: secret,
            public_key: public_key_for(&secret),
        };
        let signed = sign_message(&kp, &msg_b)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("sign_message: {e}")))?;
        let d = PyDict::new_bound(py);
        d.set_item("der", PyBytes::new_bound(py, &signed.der_bytes))?;
        d.set_item("fixed", PyBytes::new_bound(py, &signed.fixed_bytes))?;
        Ok(d)
    }
}

/// Threshold ElGamal over P-256.
#[pyclass(name = "ElGamalP256")]
pub struct PyElGamalP256;

#[pymethods]
impl PyElGamalP256 {
    /// Encapsulate a fresh shared secret against the given public key
    /// (65-byte SEC1 uncompressed). Returns
    /// `{"ciphertext": {"c1": bytes, "c2": bytes}, "shared_secret": bytes}`.
    #[staticmethod]
    fn encapsulate<'py>(
        py: Python<'py>,
        public_key: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let pk_b = bytes_arg_to_vec(public_key)?;
        let pk = ElGamalPublicKey { bytes: pk_b };
        let (ct, ss) = elgamal_encapsulate(&pk)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("encapsulate: {e}")))?;
        let ct_dict = PyDict::new_bound(py);
        ct_dict.set_item("c1", PyBytes::new_bound(py, &ct.c1))?;
        ct_dict.set_item("c2", PyBytes::new_bound(py, &ct.c2))?;
        let d = PyDict::new_bound(py);
        d.set_item("ciphertext", ct_dict)?;
        d.set_item("shared_secret", PyBytes::new_bound(py, &ss))?;
        Ok(d)
    }

    /// Compute one party's partial decryption. `share_bytes` is the
    /// 32-byte scalar share held by `party_index`.
    #[staticmethod]
    fn partial_decrypt<'py>(
        py: Python<'py>,
        party_index: u32,
        share_bytes: &Bound<'py, PyAny>,
        ciphertext: &Bound<'_, PyDict>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let share_b = bytes_arg_to_vec(share_bytes)?;
        let c1 = bytes_arg_to_vec(&ciphertext.get_item("c1")?.unwrap())?;
        let c2 = bytes_arg_to_vec(&ciphertext.get_item("c2")?.unwrap())?;
        let ct = ElGamalCiphertext { c1, c2 };
        let share = DecryptionShare {
            party_index,
            bytes: share_b,
        };
        let partial = elgamal_partial_decrypt(&share, &ct).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("partial_decrypt: {e}"))
        })?;
        let d = PyDict::new_bound(py);
        d.set_item("party_index", partial.party_index)?;
        d.set_item("bytes", PyBytes::new_bound(py, &partial.bytes))?;
        Ok(d)
    }

    /// Aggregate `partials` (a list of `{"party_index": int, "bytes":
    /// bytes}` dicts) into the recovered shared secret. `threshold` must
    /// be `<= len(partials)`.
    #[staticmethod]
    fn aggregate_partials<'py>(
        py: Python<'py>,
        partials: &Bound<'_, PyList>,
        threshold: u32,
        ciphertext: &Bound<'_, PyDict>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut owned: Vec<PartialDecryption> = Vec::with_capacity(partials.len());
        for item in partials.iter() {
            let d: Bound<'_, PyDict> = item.extract()?;
            let party_index: u32 = d.get_item("party_index")?.unwrap().extract()?;
            let bytes_value = d.get_item("bytes")?.unwrap();
            let bytes = bytes_arg_to_vec(&bytes_value)?;
            owned.push(PartialDecryption { party_index, bytes });
        }
        let c1 = bytes_arg_to_vec(&ciphertext.get_item("c1")?.unwrap())?;
        let c2 = bytes_arg_to_vec(&ciphertext.get_item("c2")?.unwrap())?;
        let ct = ElGamalCiphertext { c1, c2 };
        let ss = elgamal_aggregate(&owned, threshold, &ct).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("aggregate_partials: {e}"))
        })?;
        Ok(PyBytes::new_bound(py, &ss))
    }
}

/// CMP20 in-process threshold-ECDSA over P-256.
#[pyclass(name = "Cmp20")]
pub struct PyCmp20;

#[pymethods]
impl PyCmp20 {
    /// Run a non-interactive CMP20 DKG for `party_count` parties at
    /// threshold `threshold`. Returns
    /// `{"shares": [bytes, ...], "public_key": bytes}` where each
    /// share blob is 71 bytes (opaque Cmp20Share encoding).
    #[staticmethod]
    fn keygen<'py>(
        py: Python<'py>,
        threshold: u32,
        party_count: u32,
    ) -> PyResult<Bound<'py, PyDict>> {
        let kg = cmp20_inprocess::keygen(threshold, party_count as usize).map_err(|e| {
            threshold_err(
                "Cmp20.keygen",
                &e.to_string(),
                party_count as usize,
                threshold as usize,
            )
        })?;
        let shares = PyList::empty_bound(py);
        for s in kg.shares {
            shares.append(PyBytes::new_bound(py, &s))?;
        }
        let d = PyDict::new_bound(py);
        d.set_item("shares", shares)?;
        d.set_item("public_key", PyBytes::new_bound(py, &kg.public_key))?;
        Ok(d)
    }

    /// Threshold-sign `message` using `shares` (a list of CMP20 share
    /// blobs from a previous `keygen` call). Returns the 64-byte
    /// `(r, s)` signature.
    #[staticmethod]
    fn sign<'py>(
        py: Python<'py>,
        shares: &Bound<'_, PyList>,
        threshold: u32,
        message: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut share_bytes: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
        for item in shares.iter() {
            share_bytes.push(bytes_arg_to_vec(&item)?);
        }
        let supplied = share_bytes.len();
        let msg = bytes_arg_to_vec(message)?;
        let sig = cmp20_inprocess::sign(&share_bytes, threshold, &msg).map_err(|e| {
            threshold_err("Cmp20.sign", &e.to_string(), supplied, threshold as usize)
        })?;
        Ok(PyBytes::new_bound(py, &sig))
    }
}

/// GG18 in-process threshold-ECDSA over P-256.
#[pyclass(name = "Gg18")]
pub struct PyGg18;

#[pymethods]
impl PyGg18 {
    /// Run a GG18 DKG. Returns `{"shares": [bytes, ...], "public_key":
    /// bytes}` (same shape as `Cmp20.keygen`).
    #[staticmethod]
    fn keygen<'py>(
        py: Python<'py>,
        threshold: u32,
        party_count: u32,
    ) -> PyResult<Bound<'py, PyDict>> {
        let kg = gg18_inprocess::keygen(threshold, party_count as usize).map_err(|e| {
            threshold_err(
                "Gg18.keygen",
                &e.to_string(),
                party_count as usize,
                threshold as usize,
            )
        })?;
        let shares = PyList::empty_bound(py);
        for s in kg.shares {
            shares.append(PyBytes::new_bound(py, &s))?;
        }
        let d = PyDict::new_bound(py);
        d.set_item("shares", shares)?;
        d.set_item("public_key", PyBytes::new_bound(py, &kg.public_key))?;
        Ok(d)
    }

    /// Threshold-sign `message` with `shares`. Returns the 64-byte
    /// `(r, s)` signature.
    #[staticmethod]
    fn sign<'py>(
        py: Python<'py>,
        shares: &Bound<'_, PyList>,
        threshold: u32,
        message: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut share_bytes: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
        for item in shares.iter() {
            share_bytes.push(bytes_arg_to_vec(&item)?);
        }
        let supplied = share_bytes.len();
        let msg = bytes_arg_to_vec(message)?;
        let sig = gg18_inprocess::sign(&share_bytes, threshold, &msg).map_err(|e| {
            threshold_err("Gg18.sign", &e.to_string(), supplied, threshold as usize)
        })?;
        Ok(PyBytes::new_bound(py, &sig))
    }
}

/// Build a `PyRuntimeError` whose message carries a structured
/// `[confium:threshold]` prefix. The pure-Python `confium.errors`
/// translator parses this prefix to convert the bare RuntimeError
/// into a typed `ThresholdError` — see
/// `python/confium/errors.py::_classify`.
///
/// Format: `[confium:threshold] have=N need=M operation=OP :: <human msg>`
///
/// The format is stable: it depends only on the prefix tokens
/// (`confium:threshold`, `have=`, `need=`, `operation=`), not on
/// the snafu Display string. Changes to upstream Rust error
/// messages cannot break the translator.
fn threshold_err(operation: &str, human_msg: &str, have: usize, need: usize) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!(
        "[confium:threshold] have={have} need={need} operation={operation} :: {human_msg}"
    ))
}

/// Register the `tc` submodule.
pub(crate) fn register_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new_bound(py, "tc")?;
    m.add_class::<PyFrostP256>()?;
    m.add_class::<PyElGamalP256>()?;
    m.add_class::<PyCmp20>()?;
    m.add_class::<PyGg18>()?;
    parent.add_submodule(&m)?;
    Ok(())
}
