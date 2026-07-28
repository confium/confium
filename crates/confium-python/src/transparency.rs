//! Transparency log (Merkle tree) operations.
//!
//! Mirrors the Ruby `Confium::Transparency::MerkleTree` API.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use confium_transparency::{MerkleTree as RustMerkleTree, MerkleEntry, ArtifactType};

/// An append-only Merkle tree (RFC 6962).
#[pyclass]
pub struct MerkleTree {
    inner: RustMerkleTree,
}

/// An inclusion proof for a Merkle tree entry.
#[pyclass]
pub struct InclusionProof {
    inner: confium_transparency::InclusionProof,
}

#[pymethods]
impl MerkleTree {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustMerkleTree::new(),
        }
    }

    /// Append an entry to the tree.
    ///
    /// Args:
    ///     artifact_type: String like "certificate_issuance".
    ///     artifact_hash: 32-byte SHA-256 hash of the artifact.
    ///
    /// Returns:
    ///     The sequence number (u64) of the appended entry.
    fn append(
        &mut self,
        artifact_type: &str,
        artifact_hash: &[u8],
    ) -> PyResult<u64> {
        let at = match artifact_type {
            "certificate_issuance" => ArtifactType::CertificateIssuance,
            "certificate_revocation" => ArtifactType::CertificateRevocation,
            "policy_change" => ArtifactType::PolicyChange,
            _ => ArtifactType::CertificateIssuance,
        };

        let mut hash = [0u8; 32];
        if artifact_hash.len() >= 32 {
            hash.copy_from_slice(&artifact_hash[..32]);
        }

        let seq = self.inner.len() as u64;
        let entry = MerkleEntry::new(seq, at, hash);
        let assigned = self.inner.append(entry);
        Ok(assigned)
    }

    /// Current root hash (32 bytes). Empty tree returns all-zeros.
    #[getter]
    fn root<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.root())
    }

    /// Number of entries in the tree.
    #[getter]
    fn size(&self) -> usize {
        self.inner.len()
    }

    /// Compute an inclusion proof for the entry at `sequence`.
    fn inclusion_proof(&self, sequence: u64) -> PyResult<InclusionProof> {
        let proof = self
            .inner
            .inclusion_proof(sequence)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))?;
        Ok(InclusionProof { inner: proof })
    }
}

#[pymethods]
impl InclusionProof {
    /// The sequence number this proof covers.
    #[getter]
    fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    /// Number of steps in the proof.
    #[getter]
    fn len(&self) -> usize {
        self.inner.steps.len()
    }
}

/// Verify an inclusion proof against a root hash.
///
/// Args:
///     entry_hash: 32-byte hash of the entry being proven.
///     proof: The InclusionProof to verify.
///     root: 32-byte root hash to check against.
///
/// Returns True if valid. Raises ValueError if invalid.
#[pyfunction]
fn verify_inclusion(
    entry_hash: &[u8],
    proof: &InclusionProof,
    root: &[u8],
) -> PyResult<bool> {
    let mut hash = [0u8; 32];
    if entry_hash.len() >= 32 {
        hash.copy_from_slice(&entry_hash[..32]);
    }

    let mut root_hash = [0u8; 32];
    if root.len() >= 32 {
        root_hash.copy_from_slice(&root[..32]);
    }

    // Build a temporary MerkleEntry for verification.
    let entry = MerkleEntry::new(proof.inner.sequence, ArtifactType::CertificateIssuance, hash);

    RustMerkleTree::verify_inclusion(&entry, &proof.inner, root_hash)
        .map(|_| true)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
