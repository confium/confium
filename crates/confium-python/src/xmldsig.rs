//! XMLDSig canonicalization bindings.
//!
//! Exposes [`confium_pki::xmldsig`] canonicalization functions to Python:
//!
//! - [`xmldsig_canonicalize`] — RFC 3076 canonical XML
//! - [`xmldsig_canonicalize_exclusive`] — Exclusive C14N (RFC 3741)

use pyo3::prelude::*;

/// Canonicalize XML per RFC 3076 (Canonical XML 1.0).
///
/// Strips the XML declaration, normalizes whitespace, and produces
/// the canonical form used for XMLDSig signature verification.
#[pyfunction]
fn canonicalize(xml: &str) -> PyResult<String> {
    confium_pki::xmldsig::canonicalize(xml).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(e.to_string())
    })
}

/// Canonicalize XML per Exclusive C14N (RFC 3741).
///
/// Used by XMLDSig when the signed content includes namespaces that
/// should NOT be visible in the canonical form (e.g., SOAP envelopes).
#[pyfunction]
fn canonicalize_exclusive(xml: &str) -> PyResult<String> {
    confium_pki::xmldsig::canonicalize_exclusive(xml).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(e.to_string())
    })
}

/// Compute the SHA-256 digest of `data` as 32 bytes.
///
/// Convenience function for XMLDSig reference digest calculation.
#[pyfunction]
fn sha256_digest<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, pyo3::types::PyBytes> {
    pyo3::types::PyBytes::new_bound(py, &confium_pki::xmldsig::sha256_digest(data))
}

/// Register the `xmldsig` submodule.
pub(crate) fn register_module(
    py: Python<'_>,
    parent: &Bound<'_, PyModule>,
) -> PyResult<()> {
    let m = PyModule::new_bound(py, "xmldsig")?;
    m.add_function(wrap_pyfunction!(canonicalize, &m)?)?;
    m.add_function(wrap_pyfunction!(canonicalize_exclusive, &m)?)?;
    m.add_function(wrap_pyfunction!(sha256_digest, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}
