//! Transparency log (Merkle tree) operations.
//!
//! Exposes the [`confium_transparency`] crate's append-only Merkle tree
//! to Python. Implements RFC 6962-style inclusion proofs with SHA-256
//! domain separation (0x01 prefix for leaves, 0x02 for internal nodes).
//!
//! Two verification entry points are provided:
//!
//! - [`MerkleTree::verify_inclusion`] — round-trip verification that
//!   looks up the entry by sequence number. Use this when you own the
//!   tree (e.g. in tests, internal services).
//! - [`verify_inclusion_with_leaf`] — proves a published leaf hash is
//!   part of a published root. Use this as an external auditor when
//!   you only have the leaf hash + proof + root, not the tree itself.
//!
//! Python usage:
//!   ```python
//!   from confium import transparency
//!
//!   tree = transparency.MerkleTree()
//!   seq = tree.append("certificate_issuance", artifact_hash_bytes)
//!   root = tree.root
//!   proof = tree.inclusion_proof(seq)
//!   tree.verify_inclusion(seq, proof, root)  # round-trip
//!   ```

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3::Bound;

use confium_transparency::{
    ArtifactType, Hash, InclusionProof as RustInclusionProof, MerkleEntry,
    MerkleTree as RustMerkleTree, Side,
};
use sha2::{Digest, Sha256};

fn parse_artifact_type(s: &str) -> PyResult<ArtifactType> {
    use std::str::FromStr;
    ArtifactType::from_str(s)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

fn artifact_type_str(at: ArtifactType) -> &'static str {
    at.as_str()
}

fn require_hash_32(buf: &[u8], field: &str) -> PyResult<Hash> {
    if buf.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "{field} must be exactly 32 bytes (got {})",
            buf.len()
        )));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(buf);
    Ok(h)
}

fn hash_internal(left: Hash, right: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x02]);
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn hash_leaf(entry_hash: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(entry_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// An append-only Merkle tree (RFC 6962).
#[pyclass]
pub struct MerkleTree {
    inner: RustMerkleTree,
}

/// An inclusion proof for a Merkle tree entry. Holds the sequence
/// number being proven plus the list of (sibling_hash, side) steps
/// from leaf to root.
#[pyclass(name = "InclusionProof")]
pub struct PyInclusionProof {
    inner: RustInclusionProof,
}

#[pymethods]
impl MerkleTree {
    /// Construct a new empty tree.
    #[new]
    fn new() -> Self {
        Self {
            inner: RustMerkleTree::new(),
        }
    }

    /// Append an entry to the tree.
    ///
    /// Args:
    ///     artifact_type: One of the strings in `transparency.ARTIFACT_TYPES`.
    ///     artifact_hash: 32-byte SHA-256 hash of the artifact.
    ///
    /// Returns:
    ///     The sequence number (u64) assigned to the entry.
    fn append(
        &mut self,
        artifact_type: &str,
        artifact_hash: &Bound<'_, PyBytes>,
    ) -> PyResult<u64> {
        let at = parse_artifact_type(artifact_type)?;
        let hash = require_hash_32(artifact_hash.as_bytes(), "artifact_hash")?;
        let seq = self.inner.len() as u64;
        let entry = MerkleEntry::new(seq, at, hash);
        Ok(self.inner.append(entry))
    }

    /// Current root hash (32 bytes). Empty tree returns all-zeros.
    #[getter]
    fn root<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.root())
    }

    /// Number of entries in the tree.
    #[getter]
    fn size(&self) -> usize {
        self.inner.len()
    }

    /// True iff the tree has no entries.
    #[getter]
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Compute an inclusion proof for the entry at `sequence`.
    fn inclusion_proof(&self, sequence: u64) -> PyResult<PyInclusionProof> {
        let proof = self
            .inner
            .inclusion_proof(sequence)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))?;
        Ok(PyInclusionProof { inner: proof })
    }

    /// Compute a consistency proof (RFC 6962 §2.1.2).
    ///
    /// Returns the list of subtree hashes that prove the tree's first
    /// `old_size` entries hash to the same root as a standalone tree
    /// of `old_size` entries.
    ///
    /// Use [`verify_consistency`][crate::verify_consistency] to verify.
    fn consistency_proof<'py>(
        &self,
        py: Python<'py>,
        old_size: usize,
    ) -> PyResult<Bound<'py, PyList>> {
        let proof = self
            .inner
            .consistency_proof(old_size)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let list = PyList::empty_bound(py);
        for hash in proof {
            list.append(PyBytes::new_bound(py, &hash))?;
        }
        Ok(list)
    }

    /// Return the entry at `sequence`, or raise IndexError if out of range.
    ///
    /// Returns a dict with keys: `sequence`, `timestamp` (ISO 8601 string),
    /// `artifact_type`, `artifact_hash` (bytes).
    fn entry<'py>(
        &self,
        py: Python<'py>,
        sequence: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let e = self
            .inner
            .entry(sequence)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))?;
        let dict = PyDict::new_bound(py);
        dict.set_item("sequence", e.sequence)?;
        dict.set_item("timestamp", e.timestamp.to_rfc3339())?;
        dict.set_item("artifact_type", artifact_type_str(e.artifact_type))?;
        dict.set_item("artifact_hash", PyBytes::new_bound(py, &e.artifact_hash))?;
        Ok(dict)
    }

    /// Round-trip inclusion verification: looks up the entry at
    /// `sequence` in this tree, then verifies `proof` against `root`.
    ///
    /// Use this when you own the tree. External auditors should use
    /// [`verify_inclusion_with_leaf`][crate::verify_inclusion_with_leaf]
    /// with a published leaf hash instead.
    fn verify_inclusion(
        &self,
        sequence: u64,
        proof: &PyInclusionProof,
        root: &Bound<'_, PyBytes>,
    ) -> PyResult<()> {
        let entry = self
            .inner
            .entry(sequence)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))?;
        let root_hash = require_hash_32(root.as_bytes(), "root")?;
        RustMerkleTree::verify_inclusion(entry, &proof.inner, root_hash)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Verify a consistency proof (RFC 6962 §2.1.2).
    ///
    /// Brute-force: recomputes the tree's root at `old_size` and its
    /// current root, then compares to `old_root` and `new_root`.
    ///
    /// Requires `&self` because external proof-only verification (no
    /// tree access) requires a much more intricate algorithm. For the
    /// common case where the verifier owns the tree (tests, internal
    /// services, log owners), this method is correct and sufficient.
    ///
    /// Args:
    ///     old_root: 32-byte root of the tree at `old_size`.
    ///     new_root: 32-byte root of the current tree.
    ///     old_size: Prior tree size.
    ///     new_size: Current tree size (must equal `tree.size`).
    ///     proof:    Consistency proof from `MerkleTree.consistency_proof`
    ///               (currently unused by the brute-force verifier, but
    ///               accepted for API symmetry with inclusion proofs).
    fn verify_consistency(
        &self,
        old_root: &Bound<'_, PyBytes>,
        new_root: &Bound<'_, PyBytes>,
        old_size: usize,
        new_size: usize,
        proof: &Bound<'_, PyList>,
    ) -> PyResult<()> {
        let old_root_hash = require_hash_32(old_root.as_bytes(), "old_root")?;
        let new_root_hash = require_hash_32(new_root.as_bytes(), "new_root")?;
        let mut proof_hashes: Vec<Hash> = Vec::with_capacity(proof.len());
        for item in proof.iter() {
            let bytes: Vec<u8> = item.extract()?;
            proof_hashes.push(require_hash_32(&bytes, "proof entry")?);
        }
        self.inner
            .verify_consistency(old_root_hash, new_root_hash, old_size, new_size, &proof_hashes)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
}

#[pymethods]
impl PyInclusionProof {
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

    /// True iff the proof has zero steps (single-leaf tree).
    #[getter]
    fn is_empty(&self) -> bool {
        self.inner.steps.is_empty()
    }

    /// Steps as a list of dicts: `{"sibling": bytes(32), "side": "left"|"right"}`.
    #[getter]
    fn steps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        for step in &self.inner.steps {
            let dict = PyDict::new_bound(py);
            dict.set_item("sibling", PyBytes::new_bound(py, &step.sibling))?;
            let side_str = match step.side {
                Side::Left => "left",
                Side::Right => "right",
            };
            dict.set_item("side", side_str)?;
            list.append(dict)?;
        }
        Ok(list)
    }

    fn __repr__(&self) -> String {
        format!(
            "<InclusionProof sequence={} steps={}>",
            self.inner.sequence,
            self.inner.steps.len()
        )
    }
}

/// Compute the leaf hash stored in the tree for an entry with the
/// given (sequence, timestamp, artifact_hash).
///
/// The leaf hash is `SHA-256(0x01 || entry_hash)`, where
/// `entry_hash = SHA-256(sequence_le || timestamp_micros_le || artifact_hash)`.
///
/// Use this when verifying a published transparency log entry: the
/// log publishes sequence + timestamp + artifact_hash, and auditors
/// recompute the leaf hash to verify inclusion.
#[pyfunction]
#[pyo3(signature = (sequence, timestamp, artifact_hash))]
fn compute_leaf_hash<'py>(
    py: Python<'py>,
    sequence: u64,
    timestamp: &'py str,
    artifact_hash: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let artifact = require_hash_32(artifact_hash.as_bytes(), "artifact_hash")?;
    let ts: chrono::DateTime<chrono::Utc> = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "timestamp must be RFC 3339 (got '{timestamp}'): {e}"
            ))
        })?
        .with_timezone(&chrono::Utc);

    let mut entry_hasher = Sha256::new();
    entry_hasher.update(sequence.to_le_bytes());
    entry_hasher.update(ts.timestamp_micros().to_le_bytes());
    entry_hasher.update(artifact);
    let mut entry_hash = [0u8; 32];
    entry_hash.copy_from_slice(&entry_hasher.finalize());

    Ok(PyBytes::new_bound(py, &hash_leaf(entry_hash)))
}

/// Verify an inclusion proof given a precomputed leaf hash.
///
/// This is the external-auditor entry point: given a published leaf
/// hash, a proof, and a published root, returns `None` on success or
/// raises `ValueError` on failure.
#[pyfunction]
fn verify_inclusion_with_leaf(
    leaf_hash: &Bound<'_, PyBytes>,
    proof: &PyInclusionProof,
    root: &Bound<'_, PyBytes>,
) -> PyResult<()> {
    let mut current = require_hash_32(leaf_hash.as_bytes(), "leaf_hash")?;
    let root_hash = require_hash_32(root.as_bytes(), "root")?;

    for step in &proof.inner.steps {
        current = match step.side {
            Side::Left => hash_internal(step.sibling, current),
            Side::Right => hash_internal(current, step.sibling),
        };
    }

    use subtle::ConstantTimeEq;
    let ok: bool = current.ct_eq(&root_hash).into();
    if ok {
        Ok(())
    } else {
        Err(pyo3::exceptions::PyValueError::new_err(format!(
            "inclusion proof failed for sequence {}",
            proof.inner.sequence
        )))
    }
}

/// Register the `transparency` submodule.
pub(crate) fn register_module(
    py: Python<'_>,
    parent: &Bound<'_, PyModule>,
) -> PyResult<()> {
    let m = PyModule::new_bound(py, "transparency")?;
    m.add_class::<MerkleTree>()?;
    m.add_class::<PyInclusionProof>()?;
    m.add_function(wrap_pyfunction!(compute_leaf_hash, &m)?)?;
    m.add_function(wrap_pyfunction!(verify_inclusion_with_leaf, &m)?)?;

    let artifact_types = PyList::empty_bound(py);
    for name in [
        "certificate_issuance",
        "certificate_revocation",
        "threshold_signature",
        "threshold_encryption",
        "director_rotation",
        "quorum_policy",
        "director_identity",
        "archive_renewal",
    ] {
        artifact_types.append(name)?;
    }
    m.add("ARTIFACT_TYPES", artifact_types)?;

    parent.add_submodule(&m)?;
    Ok(())
}
