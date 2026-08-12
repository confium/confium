//! Evidence Record Syntax (ERS, RFC 4998) bindings — long-term archival.

use pyo3::prelude::*;

use confium_transparency::ers::{
    EvidenceRecord, HashAlgorithm, build_initial_evidence_record, renew_evidence_record,
    renewal_count,
};

/// An RFC 4998 Evidence Record for long-term archival protection.
#[pyclass(name = "EvidenceRecord")]
pub struct PyEvidenceRecord {
    inner: EvidenceRecord,
}

fn require_hash_32(buf: &[u8], field: &str) -> PyResult<[u8; 32]> {
    if buf.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "{field} must be 32 bytes"
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(buf);
    Ok(arr)
}

#[pymethods]
impl PyEvidenceRecord {
    /// Build the initial evidence record for a data hash.
    ///
    /// Args:
    ///     data_hash: 32-byte hash of the archived data.
    ///     tsa_id: Timestamping authority identifier string.
    ///     timestamp_token: Opaque timestamp token bytes from the TSA.
    #[staticmethod]
    fn build_initial(data_hash: &[u8], tsa_id: &str, timestamp_token: Vec<u8>) -> PyResult<Self> {
        let hash = require_hash_32(data_hash, "data_hash")?;
        let inner =
            build_initial_evidence_record(hash, HashAlgorithm::Sha256, tsa_id, timestamp_token);
        Ok(Self { inner })
    }

    /// Renew the evidence record with a new timestamp from a TSA.
    /// Returns a new EvidenceRecord (the original is unchanged).
    ///
    /// Args:
    ///     new_hash: Recomputed hash of the archived data (may differ if
    ///               the hash algorithm was upgraded).
    ///     tsa_id: Timestamping authority identifier.
    ///     timestamp_token: New opaque timestamp token bytes.
    fn renew(&self, new_hash: &[u8], tsa_id: &str, timestamp_token: Vec<u8>) -> PyResult<Self> {
        let hash = require_hash_32(new_hash, "new_hash")?;
        let mut cloned = self.inner.clone();
        renew_evidence_record(
            &mut cloned,
            HashAlgorithm::Sha256,
            hash,
            tsa_id,
            timestamp_token,
        );
        Ok(Self { inner: cloned })
    }

    /// Number of times this record has been renewed.
    #[getter]
    fn renewal_count(&self) -> u32 {
        renewal_count(&self.inner)
    }
}

pub(crate) fn register_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new_bound(py, "ers")?;
    m.add_class::<PyEvidenceRecord>()?;
    parent.add_submodule(&m)?;
    Ok(())
}
