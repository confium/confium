//! Composite signature verification.
//!
//! Exposes the [`confium_composite`] crate to Python. A composite
//! signature bundles multiple classical/PQ component signatures over
//! the same message; verification succeeds only if every component
//! verifies.
//!
//! Python usage:
//!   ```python
//!   from confium import composite
//!
//!   cs = composite.CompositeSignature.from_json(json_payload)
//!   result = cs.verify(message_bytes)
//!   if not result.all_verified:
//!       for c in result.per_component:
//!           print(c["algorithm"], c["verified"], c.get("error"))
//!   ```
//!
//! Built-in verifiers cover Ed25519 and ECDSA-P256. Callers can pass
//! a Python callable to [`CompositeSignature::verify_with`] for custom
//! algorithms (e.g. ML-DSA once a verifier lands).

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};

/// A single component of a composite signature.
///
/// Fields:
///     algorithm: algorithm identifier string (e.g. "Ed25519", "ECDSA-P256").
///     public_key: public key bytes.
///     signature: signature bytes.
#[pyclass]
pub struct ComponentSignature {
    inner: confium_composite::ComponentSignature,
}

/// A composite signature — one or more [`ComponentSignature`]s over the
/// same message.
#[pyclass]
pub struct CompositeSignature {
    inner: confium_composite::CompositeSignature,
}

/// Aggregate result of verifying a composite signature.
#[pyclass]
pub struct VerificationResult {
    inner: confium_composite::VerificationResult,
}

#[pymethods]
impl ComponentSignature {
    /// Construct a component from algorithm + public_key + signature.
    #[new]
    #[pyo3(signature = (algorithm, public_key, signature))]
    fn new(
        algorithm: &str,
        public_key: &Bound<'_, PyBytes>,
        signature: &Bound<'_, PyBytes>,
    ) -> Self {
        Self {
            inner: confium_composite::ComponentSignature {
                algorithm: algorithm.to_string(),
                public_key: public_key.as_bytes().to_vec(),
                signature: signature.as_bytes().to_vec(),
            },
        }
    }

    /// Algorithm identifier (e.g. "Ed25519").
    #[getter]
    fn algorithm(&self) -> String {
        self.inner.algorithm.clone()
    }

    /// Public key bytes.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.public_key)
    }

    /// Signature bytes.
    #[getter]
    fn signature<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.signature)
    }
}

#[pymethods]
impl CompositeSignature {
    /// Build a composite from a list of ComponentSignature objects.
    #[new]
    fn new(components: &Bound<'_, PyList>) -> PyResult<Self> {
        let mut comps = Vec::with_capacity(components.len());
        for item in components.iter() {
            let comp: PyRef<'_, ComponentSignature> = item.extract()?;
            comps.push(comp.inner.clone());
        }
        Ok(Self {
            inner: confium_composite::CompositeSignature::new(comps),
        })
    }

    /// Sign `message` with an Ed25519 private key (32 raw bytes).
    ///
    /// Returns a fresh `CompositeSignature` containing a single
    /// Ed25519 component. Use `sign_p256` for ECDSA-P256, or compose
    /// the components manually for a hybrid.
    #[staticmethod]
    fn sign_ed25519<'py>(
        py: Python<'py>,
        private_key: &Bound<'py, PyBytes>,
        message: &Bound<'py, PyBytes>,
    ) -> PyResult<Self> {
        let pk_bytes = private_key.as_bytes();
        if pk_bytes.len() != 32 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Ed25519 private key must be 32 bytes (got {})",
                pk_bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(pk_bytes);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let msg = message.as_bytes().to_vec();
        let component = py
            .allow_threads(move || confium_composite::build_ed25519_component(&signing, &msg))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            inner: confium_composite::CompositeSignature::new(vec![component]),
        })
    }

    /// Sign `message` with an ECDSA-P256 private key (32 raw bytes).
    ///
    /// Returns a fresh `CompositeSignature` with one P-256 component
    /// (DER-encoded signature, SEC1 uncompressed public key).
    #[staticmethod]
    fn sign_p256<'py>(
        py: Python<'py>,
        private_key: &Bound<'py, PyBytes>,
        message: &Bound<'py, PyBytes>,
    ) -> PyResult<Self> {
        let pk_bytes = private_key.as_bytes();
        if pk_bytes.len() != 32 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "P-256 private key must be 32 bytes (got {})",
                pk_bytes.len()
            )));
        }
        let pk_array: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("P-256 private key must be 32 bytes"))?;
        let signing = p256::ecdsa::SigningKey::from_bytes(&pk_array.into())
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("invalid P-256 key: {e}"))
            })?;
        let msg = message.as_bytes().to_vec();
        let component = py
            .allow_threads(move || confium_composite::build_p256_component(&signing, &msg))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            inner: confium_composite::CompositeSignature::new(vec![component]),
        })
    }

    /// Parse a composite signature from a JSON string.
    ///
    /// The JSON shape mirrors the on-the-wire composite envelope:
    ///   {"components": [{"algorithm": "...", "public_key": "<base64>",
    ///                    "signature": "<base64>"}, ...]}
    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner: confium_composite::CompositeSignature =
            serde_json::from_str(json_str).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("invalid composite JSON: {e}"))
            })?;
        Ok(Self { inner })
    }

    /// Serialize the composite back to a JSON string.
    fn to_json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyString>> {
        let s = serde_json::to_string(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyString::new_bound(py, &s))
    }

    /// Number of components.
    fn component_count(&self) -> usize {
        self.inner.component_count()
    }

    /// List the algorithm identifiers present in this composite.
    fn algorithms<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        for alg in self.inner.algorithms() {
            list.append(alg)?;
        }
        Ok(list)
    }

    /// Verify using built-in Ed25519 + ECDSA-P256 verifiers.
    ///
    /// Components whose algorithm is neither Ed25519 nor ECDSA-P256
    /// are marked failed with a "no builtin verifier" error. For
    /// custom algorithms, use [`verify_with`][Self::verify_with].
    fn verify<'py>(
        &self,
        py: Python<'py>,
        message: &Bound<'py, PyBytes>,
    ) -> PyResult<VerificationResult> {
        let msg = message.as_bytes().to_vec();
        let inner = self.inner.clone();
        let result = py
            .allow_threads(move || {
                inner.verify(&msg, |alg, pk, m, sig| match alg {
                    confium_composite::ED25519 => {
                        confium_composite::ed25519_verifier(alg, pk, m, sig)
                    }
                    confium_composite::ECDSA_P256 => {
                        confium_composite::p256_verifier(alg, pk, m, sig)
                    }
                    _ => Err(format!(
                        "no builtin verifier for algorithm '{alg}' \
                         (use verify_with for custom algorithms)"
                    )),
                })
            })
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(VerificationResult { inner: result })
    }

    /// Verify with a caller-supplied verifier callback.
    ///
    /// The callback receives (algorithm, public_key, message, signature)
    /// as `(str, bytes, bytes, bytes)` and must return `None` on success
    /// or a `str` error message on failure.
    fn verify_with<'py>(
        &self,
        _py: Python<'py>,
        message: &Bound<'py, PyBytes>,
        verifier: Bound<'py, PyAny>,
    ) -> PyResult<VerificationResult> {
        let msg = message.as_bytes();
        let callback = verifier.clone();
        let result = self
            .inner
            .verify(msg, |alg, pk, m, sig| {
                Python::with_gil(|py| {
                    let args = (
                        alg.to_string(),
                        PyBytes::new_bound(py, pk),
                        PyBytes::new_bound(py, m),
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
        Ok(VerificationResult { inner: result })
    }
}

#[pymethods]
impl VerificationResult {
    /// True iff every component verified.
    #[getter]
    fn all_verified(&self) -> bool {
        self.inner.all_verified
    }

    /// Per-component results as a list of dicts, each with keys:
    /// `index`, `algorithm`, `verified`, `error` (str or None).
    #[getter]
    fn per_component<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        for c in &self.inner.per_component {
            let dict = PyDict::new_bound(py);
            dict.set_item("index", c.index)?;
            dict.set_item("algorithm", &c.algorithm)?;
            dict.set_item("verified", c.verified)?;
            match &c.error {
                Some(e) => dict.set_item("error", e)?,
                None => dict.set_item("error", py.None())?,
            }
            list.append(dict)?;
        }
        Ok(list)
    }

    fn __repr__(&self) -> String {
        format!(
            "<VerificationResult all_verified={} components={}>",
            self.inner.all_verified,
            self.inner.per_component.len()
        )
    }
}

/// Built-in Ed25519 verifier. Exposed for callers building custom
/// verifier chains.
#[pyfunction]
fn verify_ed25519(
    public_key: &Bound<'_, PyBytes>,
    message: &Bound<'_, PyBytes>,
    signature: &Bound<'_, PyBytes>,
) -> PyResult<()> {
    confium_composite::ed25519_verifier(
        confium_composite::ED25519,
        public_key.as_bytes(),
        message.as_bytes(),
        signature.as_bytes(),
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Built-in ECDSA-P256 verifier. Public key is SEC1 (compressed or
/// uncompressed); signature is DER-encoded.
#[pyfunction]
fn verify_ecdsa_p256(
    public_key: &Bound<'_, PyBytes>,
    message: &Bound<'_, PyBytes>,
    signature: &Bound<'_, PyBytes>,
) -> PyResult<()> {
    confium_composite::p256_verifier(
        confium_composite::ECDSA_P256,
        public_key.as_bytes(),
        message.as_bytes(),
        signature.as_bytes(),
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Register the `composite` submodule.
pub(crate) fn register_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new_bound(py, "composite")?;
    m.add_class::<ComponentSignature>()?;
    m.add_class::<CompositeSignature>()?;
    m.add_class::<VerificationResult>()?;
    m.add_function(wrap_pyfunction!(verify_ed25519, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_ecdsa_p256, &m)?)?;
    m.add("ED25519", confium_composite::ED25519)?;
    m.add("ECDSA_P256", confium_composite::ECDSA_P256)?;
    m.add("ML_DSA_65", confium_composite::ML_DSA_65)?;
    parent.add_submodule(&m)?;
    Ok(())
}
