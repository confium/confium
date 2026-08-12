//! Deployment bindings — identity + manifest.
//!
//! Exposes [`confium_deployment`] to Python:
//!
//! - [`Manifest`] — parse + serialize deployment manifests (TOML).
//! - [`validate_manifest`] — validate a manifest's internal consistency.

use pyo3::prelude::*;
use pyo3::types::{PyList, PyString};

use confium_deployment::{validate_manifest as rust_validate, Manifest as RustManifest,
    parse_manifest as rust_parse, manifest_to_toml as rust_to_toml};

/// A parsed deployment manifest (TOML-backed model).
///
/// Construct via [`Manifest.from_toml`].
#[pyclass(name = "Manifest")]
pub struct PyManifest {
    inner: RustManifest,
}

#[pymethods]
impl PyManifest {
    /// Parse a deployment manifest from a TOML string.
    #[staticmethod]
    fn from_toml(toml_str: &str) -> PyResult<Self> {
        let inner = rust_parse(toml_str).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("manifest parse error: {e}"))
        })?;
        Ok(Self { inner })
    }

    /// Serialize back to a TOML string.
    fn to_toml<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyString>> {
        let s = rust_to_toml(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyString::new_bound(py, &s))
    }

    /// Validate this manifest's internal consistency. Returns a list
    /// of warning/error messages (empty if valid).
    fn validate<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let report = rust_validate(&self.inner);
        let list = PyList::empty_bound(py);
        for msg in &report.warnings {
            list.append(format!("WARNING: {msg}"))?;
        }
        for msg in &report.errors {
            list.append(format!("ERROR: {msg}"))?;
        }
        Ok(list)
    }

    /// Deployment name from the manifest header.
    #[getter]
    fn name(&self) -> &str {
        &self.inner.deployment.name
    }

    /// Deployment operator from the manifest header.
    #[getter]
    fn operator(&self) -> &str {
        &self.inner.deployment.operator
    }

    /// Deployment mode ("peer_to_peer", "pki_drop_in", "sovereign_pki").
    #[getter]
    fn mode(&self) -> String {
        format!("{:?}", self.inner.mode)
    }

    /// Number of tiers in the manifest.
    #[getter]
    fn tier_count(&self) -> usize {
        self.inner.tiers.len()
    }
}

/// Register the `deployment` submodule.
pub(crate) fn register_module(
    py: Python<'_>,
    parent: &Bound<'_, PyModule>,
) -> PyResult<()> {
    let m = PyModule::new_bound(py, "deployment")?;
    m.add_class::<PyManifest>()?;
    parent.add_submodule(&m)?;
    Ok(())
}
