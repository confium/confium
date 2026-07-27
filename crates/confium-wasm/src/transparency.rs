//! `MerkleTree` + `InclusionProof` — RFC 6962 transparency log proofs.

use confium_transparency::merkle::{Hash, InclusionProof as RustInclusionProof};
use wasm_bindgen::prelude::*;

/// Append-only Merkle tree mirroring `confium_transparency::MerkleTree`.
///
/// Browser-side consumers typically receive a tree head (root hash + size)
/// from a server and verify inclusion proofs against it. This class also
/// supports building trees locally for testing.
#[wasm_bindgen]
pub struct MerkleTree {
    inner: std::cell::RefCell<confium_transparency::merkle::MerkleTree>,
    /// Stored entry hashes keyed by sequence, so inclusion proofs can be
    /// verified without round-tripping entries back through the boundary.
    leaf_hashes: std::cell::RefCell<std::collections::HashMap<u64, Hash>>,
}

#[wasm_bindgen]
impl MerkleTree {
    /// Construct an empty tree.
    #[wasm_bindgen(constructor)]
    pub fn new() -> MerkleTree {
        Self {
            inner: std::cell::RefCell::new(confium_transparency::merkle::MerkleTree::new()),
            leaf_hashes: std::cell::RefCell::new(Default::default()),
        }
    }

    /// Append a 32-byte artifact hash. Returns the assigned sequence number.
    pub fn append(&self, artifact_hash: &[u8]) -> Result<u64, JsValue> {
        if artifact_hash.len() != 32 {
            return Err(JsValue::from_str(&format!(
                "artifact_hash must be exactly 32 bytes, got {}",
                artifact_hash.len()
            )));
        }
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(artifact_hash);
        let entry = confium_transparency::entry::MerkleEntry::new(
            0,
            confium_transparency::entry::ArtifactType::CertificateIssuance,
            hash_arr,
        );
        // Compute the leaf hash before appending so we can store it for
        // later verify() calls. Mirrors the tree's internal hash_leaf.
        let leaf_hash = hash_leaf(entry.entry_hash());
        let seq = self.inner.borrow_mut().append(entry);
        self.leaf_hashes.borrow_mut().insert(seq, leaf_hash);
        Ok(seq)
    }

    /// Current number of leaves.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.inner.borrow().len()
    }

    /// Current 32-byte root.
    #[wasm_bindgen]
    pub fn root(&self) -> Vec<u8> {
        self.inner.borrow().root().to_vec()
    }

    /// Build an inclusion proof for `sequence`.
    pub fn inclusion_proof(&self, sequence: u64) -> Result<InclusionProof, JsValue> {
        let proof = self
            .inner
            .borrow()
            .inclusion_proof(sequence)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let leaf = self
            .leaf_hashes
            .borrow()
            .get(&sequence)
            .copied()
            .ok_or_else(|| JsValue::from_str("missing leaf hash for sequence"))?;
        Ok(InclusionProof {
            inner: proof,
            leaf_hash: leaf,
        })
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 6962 inclusion proof: list of (sibling_hash, side) steps from the
/// leaf to the root.
#[wasm_bindgen]
pub struct InclusionProof {
    inner: RustInclusionProof,
    leaf_hash: Hash,
}

#[wasm_bindgen]
impl InclusionProof {
    /// Sequence number of the leaf this proof is for.
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    /// Verify the proof against a 32-byte root. Returns true if the leaf
    /// hashes up to the root.
    #[wasm_bindgen]
    pub fn verify(&self, root: &[u8]) -> Result<bool, JsValue> {
        if root.len() != 32 {
            return Err(JsValue::from_str(&format!(
                "root must be exactly 32 bytes, got {}",
                root.len()
            )));
        }
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(root);
        let mut current = self.leaf_hash;
        for step in &self.inner.steps {
            current = match step.side {
                confium_transparency::merkle::Side::Left => {
                    hash_internal(step.sibling, current)
                }
                confium_transparency::merkle::Side::Right => {
                    hash_internal(current, step.sibling)
                }
            };
        }
        Ok(current == root_arr)
    }
}

// Domain-separated hash helpers — mirror the tree's internal algorithm
// (0x01 prefix for leaf, 0x02 prefix for internal). The transparency
// crate doesn't currently re-export them.
fn hash_leaf(entry_hash: Hash) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(entry_hash);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn hash_internal(left: Hash, right: Hash) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([0x02]);
    h.update(left);
    h.update(right);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}
