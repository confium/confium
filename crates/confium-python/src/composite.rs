//! Composite signature verification.
//!
//! Mirrors the Ruby `Confium::Composite::Signature` API:
//!   sig = CompositeSignature.from_json(json_str)
//!   result = sig.verify(message, {"Ed25519": "builtin", ...})

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::collections::HashMap;

/// A loaded composite signature, ready to verify.
#[pyclass]
pub struct CompositeSignature {
    inner: confium_composite::CompositeSignature,
}

/// Result of a composite signature verification.
#[pyclass]
pub struct VerificationResult {
    all_verified: bool,
    per_component: HashMap<String, bool>,
}

#[pymethods]
impl CompositeSignature {
    /// Load a composite signature from a JSON string.
    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner = confium_composite::CompositeSignature::from_json(json_str)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Verify the composite signature against a message.
    ///
    /// Args:
    ///     message: The signed message as bytes.
    ///     verifiers: Dict mapping algorithm name to "builtin" (for Ed25519
    ///                and ECDSA-P256) or a callable for custom verifiers.
    ///
    /// Returns:
    ///     VerificationResult with all_verified and per_component fields.
    fn verify<'py>(
        &self,
        py: Python<'py>,
        message: &Bound<'py, PyBytes>,
        verifiers: &Bound<'py, PyDict>,
    ) -> PyResult<VerificationResult> {
        let msg = message.as_bytes();

        // Build the verifier set. "builtin" maps to the built-in
        // Ed25519 / ECDSA-P256 verifiers. Other strings / callables
        // are not yet supported (caller-supplied verifiers need
        // a callback bridge that's TODO).
        let mut verifier_builder = confium_composite::CompositeVerifier::new();

        for (key, value) in verifiers.iter() {
            let algo: String = key.extract()?;
            let val: String = value.extract().map_err(|_| {
                pyo3::exceptions::PyNotImplementedError::new_err(
                    "Only 'builtin' verifiers are supported in this version. \
                     Caller-supplied callbacks are not yet wired.",
                )
            })?;

            if val == "builtin" {
                // Built-in verifiers for Ed25519 and ECDSA-P256 are
                // registered by default in the CompositeVerifier.
                // We skip explicit registration; the verifier handles them.
            }
        }

        // Run verification.
        let result = verifier_builder
            .verify(&self.inner, msg)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        Ok(VerificationResult {
            all_verified: result.all_verified(),
            per_component: result
                .per_component()
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
        })
    }
}

#[pymethods]
impl VerificationResult {
    #[getter]
    fn all_verified(&self) -> bool {
        self.all_verified
    }

    #[getter]
    fn per_component<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (k, v) in &self.per_component {
            dict.set_item(k, *v)?;
        }
        Ok(dict)
    }
}
