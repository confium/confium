//! PKI bindings — X.509 Certificate, CSR, and CMS SignedData.
//!
//! Exposes [`confium_pki`] to Python:
//!
//! - [`Certificate`] — parse + inspect X.509 v3 certificates (DER / PEM).
//! - [`CSR`] — parse PKCS#10 certificate signing requests.
//! - [`SignedData`] — JSON-backed CMS SignedData model + verify.
//!
//! CMS DER parsing is not yet exposed upstream; use JSON for the
//! SignedData model. Once `confium_pki::cms::from_der` lands, a
//! `SignedData.from_der` classmethod will be added here.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use pyo3::Bound;

use confium_pki::{
    cert::{Certificate as RustCert, CertificateSigningRequest as RustCsr, CertError},
    cms::{
        build_detached_signature, encode_signed_data_der, verify_signed_data, SignerVerification,
        SignedData as RustSignedData,
    },
};

fn map_cert_err(e: CertError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}

/// A parsed X.509 v3 certificate.
#[pyclass(name = "Certificate")]
pub struct PyCertificate {
    inner: RustCert,
}

/// A PKCS#10 certificate signing request.
#[pyclass(name = "CSR")]
pub struct PyCsr {
    inner: RustCsr,
}

/// A CMS SignedData envelope (RFC 5652 §5.1) — semantic model.
///
/// JSON-backed (no DER parser exposed upstream yet). Use
/// [`SignedData::from_json`] to parse and [`SignedData::to_json`] to
/// serialize.
#[pyclass(name = "SignedData")]
pub struct PySignedData {
    inner: RustSignedData,
}

/// Result of verifying a SignedData.
#[pyclass(name = "CmsVerificationResult")]
pub struct PyCmsVerificationResult {
    all_verified: bool,
    per_signer: Vec<SignerVerification>,
}

#[pymethods]
impl PyCertificate {
    /// Parse a certificate from DER bytes.
    #[staticmethod]
    fn from_der(der_bytes: &Bound<'_, PyBytes>) -> PyResult<Self> {
        let inner = RustCert::from_der(der_bytes.as_bytes()).map_err(map_cert_err)?;
        Ok(Self { inner })
    }

    /// Parse a certificate from PEM (RFC 7468) text.
    #[staticmethod]
    fn from_pem(pem: &str) -> PyResult<Self> {
        let inner = RustCert::from_pem(pem).map_err(map_cert_err)?;
        Ok(Self { inner })
    }

    /// Serialize back to DER bytes.
    fn to_der<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.to_der())
    }

    /// Serialize back to PEM text.
    fn to_pem<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyString>> {
        Ok(PyString::new_bound(py, &self.inner.to_pem()))
    }

    /// SHA-256 fingerprint as a lowercase hex string.
    #[getter]
    fn fingerprint_sha256(&self) -> String {
        self.inner.fingerprint_sha256()
    }

    /// Serial number bytes.
    #[getter]
    fn serial_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.serial_bytes())
    }

    /// Not-before validity bound as an ISO 8601 string.
    #[getter]
    fn not_before(&self) -> String {
        self.inner.not_before_chrono().to_rfc3339()
    }

    /// Not-after validity bound as an ISO 8601 string.
    #[getter]
    fn not_after(&self) -> String {
        self.inner.not_after_chrono().to_rfc3339()
    }

    /// Whether the cert is within its validity window at the given time.
    ///
    /// `now` is an ISO 8601 string (e.g. "2026-07-29T12:00:00Z").
    /// If omitted, uses the current UTC time.
    #[pyo3(signature = (now=None))]
    fn is_within_validity(&self, now: Option<&str>) -> PyResult<bool> {
        let instant = match now {
            Some(s) => chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "now must be RFC 3339 (got '{s}'): {e}"
                    ))
                })?
                .with_timezone(&chrono::Utc),
            None => chrono::Utc::now(),
        };
        Ok(self.inner.is_within_validity(instant))
    }

    /// Raw subject public key bytes from the SPKI.
    #[getter]
    fn public_key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.public_key_bytes())
    }

    fn __repr__(&self) -> String {
        format!(
            "<Certificate serial={} fingerprint={:.16}...>",
            hex::encode(self.inner.serial_bytes()),
            self.inner.fingerprint_sha256()
        )
    }
}

#[pymethods]
impl PyCsr {
    /// Parse a CSR from DER bytes.
    #[staticmethod]
    fn from_der(der_bytes: &Bound<'_, PyBytes>) -> PyResult<Self> {
        let inner = RustCsr::from_der(der_bytes.as_bytes()).map_err(map_cert_err)?;
        Ok(Self { inner })
    }

    /// Parse a CSR from PEM text.
    #[staticmethod]
    fn from_pem(pem: &str) -> PyResult<Self> {
        let inner = RustCsr::from_pem(pem).map_err(map_cert_err)?;
        Ok(Self { inner })
    }

    /// Serialize back to DER bytes.
    fn to_der<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.to_der())
    }

    /// Serialize back to PEM text.
    fn to_pem<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyString>> {
        Ok(PyString::new_bound(py, &self.inner.to_pem()))
    }

    fn __repr__(&self) -> String {
        format!("<CSR der={} bytes>", self.inner.to_der().len())
    }
}

#[pymethods]
impl PySignedData {
    /// Parse a SignedData from a JSON string (mirrors the Rust model).
    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner: RustSignedData = serde_json::from_str(json_str).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid SignedData JSON: {e}"))
        })?;
        Ok(Self { inner })
    }

    /// Build a detached CMS SignedData with one signer.
    ///
    /// Args:
    ///     signature:     bytes — pre-computed signature over the payload.
    ///     algorithm:     str   — signature algorithm OID
    ///                          (Ed25519 = "1.3.101.112",
    ///                           ECDSA-P256 = "1.2.840.10045.4.3.2").
    ///     certificates:  list[bytes] — DER cert bytes per signer.
    ///
    /// The caller signs the payload separately (typically via
    /// `composite.CompositeSignature.sign_ed25519`) and passes the
    /// resulting signature bytes here. The first certificate's first
    /// 20 bytes become the SubjectKeyIdentifier per RFC 5652 §5.3.
    #[staticmethod]
    fn build_detached(
        signature: Vec<u8>,
        algorithm: String,
        certificates: Vec<Vec<u8>>,
    ) -> PyResult<Self> {
        let inner =
            build_detached_signature(Vec::new(), &algorithm, signature, certificates)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Encode as RFC 5652 ContentInfo DER bytes.
    ///
    /// Output is parseable by `openssl cms` / `openssl pkcs7` and any
    /// standards-compliant CMS consumer.
    fn to_der<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let der = py
            .allow_threads(|| encode_signed_data_der(&self.inner))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new_bound(py, &der))
    }

    /// Serialize back to a JSON string.
    fn to_json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyString>> {
        let s = serde_json::to_string(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyString::new_bound(py, &s))
    }

    /// CMS version (typically 1).
    #[getter]
    fn version(&self) -> u32 {
        self.inner.version
    }

    /// Number of signer infos.
    #[getter]
    fn signer_count(&self) -> usize {
        self.inner.signer_infos.len()
    }

    /// Number of embedded certificates.
    #[getter]
    fn certificate_count(&self) -> usize {
        self.inner.certificates.len()
    }

    /// Verify every signer's signature against `message`.
    ///
    /// `verifier` is a callable
    /// `(signer_index: int, public_key_der: bytes, signed_bytes: bytes,
    ///   signature: bytes) -> str | None`
    /// returning `None` on success or an error string on failure.
    ///
    /// For built-in Ed25519 + ECDSA-P256 verification, use the
    /// `verify_with_builtin` method.
    fn verify<'py>(
        &self,
        _py: Python<'py>,
        message: &Bound<'py, PyBytes>,
        verifier: Bound<'py, PyAny>,
    ) -> PyResult<PyCmsVerificationResult> {
        let msg = message.as_bytes().to_vec();
        let callback = verifier.clone();
        let result = verify_signed_data(&self.inner, &msg, |idx, pk, signed, sig| {
            Python::with_gil(|py| {
                let args = (
                    idx,
                    PyBytes::new_bound(py, pk),
                    PyBytes::new_bound(py, signed),
                    PyBytes::new_bound(py, sig),
                );
                match callback.call1(args) {
                    Ok(out) => {
                        if out.is_none() {
                            Ok(())
                        } else {
                            match out.extract::<String>() {
                                Ok(s) => Err(s),
                                Err(_) => Ok(()),
                            }
                        }
                    }
                    Err(e) => Err(format!("verifier raised: {e}")),
                }
            })
        })
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyCmsVerificationResult {
            all_verified: result.all_verified,
            per_signer: result.per_signer,
        })
    }

    /// Verify using built-in Ed25519 + ECDSA-P256 verifiers.
    ///
    /// Each signer's certificate public key is checked against its
    /// signature. Public keys must be in SEC1 / Ed25519 raw format
    /// (whichever matches the signature algorithm).
    fn verify_with_builtin<'py>(
        &self,
        py: Python<'py>,
        message: &Bound<'py, PyBytes>,
    ) -> PyResult<PyCmsVerificationResult> {
        let msg = message.as_bytes().to_vec();
        let inner = self.inner.clone();
        let result = py
            .allow_threads(move || {
                verify_signed_data(&inner, &msg, |_idx, pk, signed, sig| {
                    // Try Ed25519 first (32-byte key, 64-byte sig), then ECDSA-P256 (DER sig).
                    if pk.len() == 32 && sig.len() == 64 {
                        return confium_composite::ed25519_verifier(
                            confium_composite::ED25519,
                            pk,
                            signed,
                            sig,
                        );
                    }
                    confium_composite::p256_verifier(confium_composite::ECDSA_P256, pk, signed, sig)
                })
            })
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyCmsVerificationResult {
            all_verified: result.all_verified,
            per_signer: result.per_signer,
        })
    }
}

#[pymethods]
impl PyCmsVerificationResult {
    /// True iff every signer verified.
    #[getter]
    fn all_verified(&self) -> bool {
        self.all_verified
    }

    /// Per-signer results as a list of dicts with keys: `signer_index`,
    /// `verified`, `error` (str | None), `cert_index` (int | None).
    #[getter]
    fn per_signer<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        for s in &self.per_signer {
            let dict = PyDict::new_bound(py);
            dict.set_item("signer_index", s.signer_index)?;
            dict.set_item("verified", s.verified)?;
            match &s.error {
                Some(e) => dict.set_item("error", e)?,
                None => dict.set_item("error", py.None())?,
            }
            match s.cert_index {
                Some(i) => dict.set_item("cert_index", i)?,
                None => dict.set_item("cert_index", py.None())?,
            }
            list.append(dict)?;
        }
        Ok(list)
    }

    fn __repr__(&self) -> String {
        format!(
            "<CmsVerificationResult all_verified={} signers={}>",
            self.all_verified,
            self.per_signer.len()
        )
    }
}

/// Register the `pki` submodule.
pub(crate) fn register_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new_bound(py, "pki")?;
    m.add_class::<PyCertificate>()?;
    m.add_class::<PyCsr>()?;
    m.add_class::<PySignedData>()?;
    m.add_class::<PyCmsVerificationResult>()?;
    parent.add_submodule(&m)?;
    Ok(())
}
