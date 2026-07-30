//! OpenTimestamps (OTS) bindings — anchor hashes to Bitcoin.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use pyo3::Bound;

use confium_transparency::ots::{OtsClient, OtsProof, OtsVerification};

/// An OpenTimestamps client for submitting hashes to calendar servers.
#[pyclass(name = "OtsClient")]
pub struct PyOtsClient {
    inner: OtsClient,
}

/// An OTS proof — attests that a hash was anchored at a Bitcoin block.
#[pyclass(name = "OtsProof")]
pub struct PyOtsProof {
    pub inner: OtsProof,
}

/// Result of verifying an OTS proof.
#[pyclass(name = "OtsVerification")]
pub struct PyOtsVerification {
    inner: OtsVerification,
}

fn require_hash_32(buf: &[u8], field: &str) -> PyResult<[u8; 32]> {
    if buf.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "{field} must be exactly 32 bytes (got {})",
            buf.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(buf);
    Ok(arr)
}

#[pymethods]
impl PyOtsClient {
    #[new]
    fn new() -> Self {
        Self { inner: OtsClient::new() }
    }

    #[getter]
    fn calendar_servers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        for s in self.inner.calendar_servers() {
            list.append(s)?;
        }
        Ok(list)
    }

    /// Submit a 32-byte hash for timestamping. Returns an OtsProof.
    /// Current implementation returns a mock proof (block 800000);
    /// real HTTP stamping lands with the full calendar server integration.
    fn stamp<'py>(
        &self,
        _py: Python<'py>,
        hash: &Bound<'py, PyBytes>,
    ) -> PyResult<PyOtsProof> {
        let hash_arr = require_hash_32(hash.as_bytes(), "hash")?;
        Ok(PyOtsProof {
            inner: OtsProof::new(hash_arr, 800_000),
        })
    }
}

#[pymethods]
impl PyOtsProof {
    #[getter]
    fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.hash)
    }

    #[getter]
    fn bitcoin_height(&self) -> u32 {
        self.inner.bitcoin_height
    }
}

#[pymethods]
impl PyOtsVerification {
    #[getter]
    fn valid(&self) -> bool { self.inner.valid }

    #[getter]
    fn bitcoin_height(&self) -> u32 { self.inner.bitcoin_height }

    #[getter]
    fn block_timestamp(&self) -> Option<u64> { self.inner.block_timestamp }
}

pub(crate) fn register_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new_bound(py, "ots")?;
    m.add_class::<PyOtsClient>()?;
    m.add_class::<PyOtsProof>()?;
    m.add_class::<PyOtsVerification>()?;
    parent.add_submodule(&m)?;
    Ok(())
}
