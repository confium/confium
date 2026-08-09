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
        // Pre-compute the sequence the tree will assign so the entry_hash
        // we use for the leaf_hash matches what the tree will store
        // internally. (entry_hash depends on sequence; if we let the tree
        // rewrite sequence==0 to N after the fact, our cached leaf_hash
        // would be wrong for every leaf past the first.)
        let seq = self.inner.borrow().len() as u64;
        let entry = confium_transparency::entry::MerkleEntry::new(
            seq,
            confium_transparency::entry::ArtifactType::CertificateIssuance,
            hash_arr,
        );
        let leaf_hash = hash_leaf(entry.entry_hash());
        let assigned = self.inner.borrow_mut().append(entry);
        debug_assert_eq!(assigned, seq, "predicted sequence must match assigned");
        self.leaf_hashes.borrow_mut().insert(assigned, leaf_hash);
        Ok(assigned)
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

    /// Build a consistency proof (RFC 6962 §2.1.2) for `old_size`.
    /// Returns a flat array of 32-byte subtree hashes concatenated
    /// (total length = proof.len() * 32).
    pub fn consistency_proof(&self, old_size: usize) -> Result<Vec<u8>, JsValue> {
        let proof = self
            .inner
            .borrow()
            .consistency_proof(old_size)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let mut flat = Vec::with_capacity(proof.len() * 32);
        for h in &proof {
            flat.extend_from_slice(h);
        }
        Ok(flat)
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
                confium_transparency::merkle::Side::Left => hash_internal(step.sibling, current),
                confium_transparency::merkle::Side::Right => hash_internal(current, step.sibling),
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

/// Compute the SHA-256 of an artifact's bytes. Useful when a client
/// only has the artifact (e.g. a cert DER) and needs the leaf hash
/// input for the inclusion-proof verifier.
///
/// # Example
///
/// ```js
/// import init, { compute_artifact_hash } from "@confium/confium-wasm";
/// await init();
/// const h = compute_artifact_hash(certDerBytes);  // Uint8Array(32)
/// ```
#[wasm_bindgen]
pub fn compute_artifact_hash(artifact_bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(artifact_bytes);
    let r = h.finalize();
    r.to_vec()
}

/// Compute the Merkle leaf hash for an entry. The leaf hash is
/// `SHA-256(0x01 || entry_hash)` where `entry_hash` is
/// `SHA-256(sequence_le_bytes || timestamp_micros_le_bytes || artifact_hash)`.
///
/// Callers who already know the leaf hash for a given sequence should
/// pass that directly to [`verify_inclusion_with_head`]. This helper is
/// for callers who only have the raw artifact + the sequence metadata
/// published by the log.
///
/// # Arguments
///
/// * `sequence` — monotonic sequence number assigned by the log.
/// * `timestamp_ms` — Unix epoch milliseconds when the entry was
///   appended (matches the entry's timestamp in the log).
/// * `artifact_bytes` — the raw artifact whose SHA-256 was anchored.
///
/// # Returns
///
/// 32-byte leaf hash as `Uint8Array`.
#[wasm_bindgen]
pub fn compute_leaf_hash(sequence: u64, timestamp_ms: f64, artifact_bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    // entry_hash = SHA-256(sequence_le || timestamp_micros_le || artifact_hash)
    let artifact_hash = {
        let mut h = Sha256::new();
        h.update(artifact_bytes);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };
    let mut entry_hasher = Sha256::new();
    entry_hasher.update(sequence.to_le_bytes());
    entry_hasher.update((timestamp_ms as i64).to_le_bytes());
    entry_hasher.update(artifact_hash);
    let entry_hash: [u8; 32] = {
        let r = entry_hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };
    hash_leaf(entry_hash).to_vec()
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

/// Tree head — snapshot of a transparency log at a given size. JSON shape:
/// `{ "size": number, "root": number[] }` (root is a 32-element Uint8Array
/// marshaled via serde as a number array). Use [`tree_head_from_json`] /
/// [`tree_head_to_json`] to round-trip heads published by a transparency-log
/// server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreeHead {
    /// Number of leaves in the tree at this head.
    pub size: usize,
    /// 32-byte SHA-256 root hash.
    pub root: Vec<u8>,
}

/// Parse a tree head from JSON. Returns a JSON string with `{ size, root_hex }`
/// (root as hex string because wasm-bindgen doesn't natively marshal Vec<u8>
/// in return position of free functions easily).
#[wasm_bindgen]
pub fn tree_head_from_json(json: &str) -> Result<String, JsValue> {
    let head: TreeHead = serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&format!("TreeHead JSON parse error: {e}")))?;
    serde_json::to_string(&serde_json::json!({
        "size": head.size,
        "root_hex": head.root.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
    }))
    .map_err(|e| JsValue::from_str(&format!("serialize: {e}")))
}

/// Verify an inclusion proof against a tree head, without needing to build
/// the tree. Caller supplies the leaf's entry hash (the digest of the
/// artifact being proven present), the proof itself (JSON form as produced
/// by `MerkleTree::inclusion_proof` + serde), and the tree head (root +
/// size).
#[wasm_bindgen]
pub fn verify_inclusion_with_head(
    leaf_entry_hash: &[u8],
    proof_json: &str,
    head_json: &str,
) -> Result<bool, JsValue> {
    if leaf_entry_hash.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "leaf_entry_hash must be 32 bytes, got {}",
            leaf_entry_hash.len()
        )));
    }
    let mut leaf_arr = [0u8; 32];
    leaf_arr.copy_from_slice(leaf_entry_hash);

    let proof: RustInclusionProof = serde_json::from_str(proof_json)
        .map_err(|e| JsValue::from_str(&format!("proof JSON parse: {e}")))?;
    let head: TreeHead = serde_json::from_str(head_json)
        .map_err(|e| JsValue::from_str(&format!("head JSON parse: {e}")))?;
    if head.root.len() != 32 {
        return Err(JsValue::from_str("head.root must be 32 bytes"));
    }
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&head.root);

    let mut current = hash_leaf(leaf_arr);
    for step in &proof.steps {
        current = match step.side {
            confium_transparency::merkle::Side::Left => hash_internal(step.sibling, current),
            confium_transparency::merkle::Side::Right => hash_internal(current, step.sibling),
        };
    }
    Ok(current == root_arr)
}
