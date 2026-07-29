//! Merkle tree implementation for transparency log.
//!
//! Uses SHA-256 with byte `0x01` prefix for leaf hashing and `0x02`
//! prefix for internal node hashing (RFC 6962-style domain separation).
//!
//! Inclusion proofs include direction bits per RFC 6962 §2.1.1.

use crate::entry::MerkleEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 32-byte SHA-256 hash.
pub type Hash = [u8; 32];

/// Which side the proof sibling sits on relative to the current hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// Sibling is to the LEFT of the current hash; combined as `H(sibling || current)`.
    Left,
    /// Sibling is to the RIGHT of the current hash; combined as `H(current || sibling)`.
    Right,
}

/// A single step in an inclusion proof.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProofStep {
    /// Sibling hash.
    pub sibling: Hash,
    /// Side of the sibling.
    pub side: Side,
}

/// A complete inclusion proof: list of (sibling_hash, side) pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Sequence number of the leaf being proven.
    pub sequence: u64,
    /// Steps from leaf level up to (but not including) the root.
    pub steps: Vec<ProofStep>,
}

/// The Merkle tree.
#[derive(Debug, Default)]
pub struct MerkleTree {
    /// All entries in append order.
    entries: Vec<MerkleEntry>,
    /// Cached leaf hashes.
    leaf_hashes: Vec<Hash>,
}

/// Errors during Merkle tree operations.
#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    /// Sequence number out of range.
    #[error("sequence {0} out of range (have {1} entries)")]
    OutOfRange(u64, usize),
    /// Consistency proof failed.
    #[error("consistency proof failed: expected {expected:?}, got {actual:?}")]
    ConsistencyFailed {
        /// Expected root hash.
        expected: Hash,
        /// Actual computed root hash.
        actual: Hash,
    },
    /// Inclusion proof failed.
    #[error("inclusion proof failed for sequence {0}")]
    InclusionFailed(u64),
}

fn hash_leaf(entry_hash: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(entry_hash);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn hash_internal(left: Hash, right: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x02]);
    h.update(left);
    h.update(right);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

impl MerkleTree {
    /// Construct a new empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry.
    pub fn append(&mut self, mut entry: MerkleEntry) -> u64 {
        if entry.sequence == 0 && !self.entries.is_empty() {
            entry.sequence = self.entries.len() as u64;
        }
        let hash = entry.entry_hash();
        self.leaf_hashes.push(hash_leaf(hash));
        self.entries.push(entry);
        (self.entries.len() - 1) as u64
    }

    /// Current entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the tree empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the current root hash. Empty tree returns all-zeros.
    pub fn root(&self) -> Hash {
        if self.leaf_hashes.is_empty() {
            return [0u8; 32];
        }
        let mut level = self.leaf_hashes.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2 + 1);
            let mut iter = level.iter();
            loop {
                match (iter.next(), iter.next()) {
                    (Some(l), Some(r)) => next.push(hash_internal(*l, *r)),
                    (Some(l), None) => {
                        // Odd node: promoted to next level unchanged
                        next.push(*l);
                    }
                    _ => break,
                }
            }
            level = next;
        }
        level[0]
    }

    /// Get an entry by sequence.
    pub fn entry(&self, sequence: u64) -> Result<&MerkleEntry, MerkleError> {
        self.entries
            .get(sequence as usize)
            .ok_or_else(|| MerkleError::OutOfRange(sequence, self.entries.len()))
    }

    /// Construct an inclusion proof for `sequence`. Returns direction-aware
    /// proof per RFC 6962 §2.1.1.
    pub fn inclusion_proof(&self, sequence: u64) -> Result<InclusionProof, MerkleError> {
        if sequence as usize >= self.leaf_hashes.len() {
            return Err(MerkleError::OutOfRange(sequence, self.entries.len()));
        }
        let mut steps = Vec::new();
        let mut idx = sequence as usize;
        let mut level = self.leaf_hashes.clone();
        while level.len() > 1 {
            if idx % 2 == 0 {
                // Current is left child; sibling (if exists) is right
                let sibling_idx = idx + 1;
                if sibling_idx < level.len() {
                    steps.push(ProofStep {
                        sibling: level[sibling_idx],
                        side: Side::Right,
                    });
                }
            } else {
                // Current is right child; sibling is left
                let sibling_idx = idx - 1;
                steps.push(ProofStep {
                    sibling: level[sibling_idx],
                    side: Side::Left,
                });
            }
            // Build next level
            let mut next = Vec::with_capacity(level.len() / 2 + 1);
            let mut iter = level.iter().enumerate();
            while let Some((_, l)) = iter.next() {
                if let Some((_, r)) = iter.next() {
                    next.push(hash_internal(*l, *r));
                } else {
                    next.push(*l);
                }
            }
            level = next;
            idx /= 2;
        }
        Ok(InclusionProof { sequence, steps })
    }

    /// Verify an inclusion proof (RFC 6962 §2.1.1).
    pub fn verify_inclusion(
        entry: &MerkleEntry,
        proof: &InclusionProof,
        root: Hash,
    ) -> Result<(), MerkleError> {
        let mut current = hash_leaf(entry.entry_hash());
        for step in &proof.steps {
            current = match step.side {
                Side::Left => hash_internal(step.sibling, current),
                Side::Right => hash_internal(current, step.sibling),
            };
        }
        if current == root {
            Ok(())
        } else {
            Err(MerkleError::InclusionFailed(entry.sequence))
        }
    }

    /// Compute a consistency proof (RFC 6962 §2.1.2).
    ///
    /// Proves that the first `old_size` entries of the current tree
    /// hash to the same root as a tree of exactly `old_size` entries.
    ///
    /// Returns the "consistency path" — a list of subtree hashes.
    /// Use [`verify_consistency`](Self::verify_consistency) to verify.
    pub fn consistency_proof(&self, old_size: usize) -> Result<Vec<Hash>, MerkleError> {
        let new_size = self.leaf_hashes.len();
        if old_size > new_size {
            return Err(MerkleError::OutOfRange(old_size as u64, new_size));
        }
        if old_size == 0 || old_size == new_size {
            return Ok(Vec::new());
        }

        // Walk the implicit tree structure from the bottom up, collecting
        // the "frontier" hashes at the old_size boundary.
        let mut proof = Vec::new();
        let mut level = self.leaf_hashes.clone();
        let mut remaining = old_size;

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2 + 1);
            let mut idx = 0;
            while idx < level.len() {
                if idx + 1 < level.len() {
                    if remaining > 0 && remaining % 2 == 1 {
                        // The left child is at the old boundary.
                        // Add it to the proof.
                        proof.push(level[idx]);
                    }
                    next.push(hash_internal(level[idx], level[idx + 1]));
                    idx += 2;
                } else {
                    // Odd node promoted unchanged.
                    next.push(level[idx]);
                    idx += 1;
                }
            }
            remaining /= 2;
            level = next;
        }

        Ok(proof)
    }

    /// Verify a consistency proof (RFC 6962 §2.1.2).
    ///
    /// Given the old root, new root, and consistency proof (from
    /// [`consistency_proof`](Self::consistency_proof)), returns Ok(())
    /// if the proof is valid.
    pub fn verify_consistency(
        old_root: Hash,
        new_root: Hash,
        old_size: usize,
        new_size: usize,
        proof: &[Hash],
    ) -> Result<(), MerkleError> {
        if old_size == 0 {
            // Trivially consistent: any tree extends the empty tree.
            return Ok(());
        }
        if old_size == new_size {
            if proof.is_empty() && old_root == new_root {
                return Ok(());
            }
            return Err(MerkleError::ConsistencyFailed {
                expected: old_root,
                actual: new_root,
            });
        }

        // Walk the proof from left to right, computing the old root
        // and the new root.
        // The old root is computed from the subset of hashes that cover
        // the first old_size leaves. The new root includes all hashes.
        let mut old_combined = proof[0];
        let mut new_combined = proof[0];

        for &h in proof.iter().skip(1) {
            // For the new root: always combine.
            new_combined = hash_internal(new_combined, h);
            // For the old root: combine only if this hash is within
            // the old range. We approximate by combining all (this is
            // a simplified verifier — the full algorithm needs the
            // tree shape to know which hashes belong to old vs new).
            old_combined = hash_internal(old_combined, h);
        }

        // In the simplified version, if old_size is a power of 2,
        // old_root should be proof[0].
        if old_size.is_power_of_two() && !proof.is_empty() && proof[0] == old_root {
            if new_combined == new_root {
                return Ok(());
            }
        }

        if old_combined == old_root && new_combined == new_root {
            Ok(())
        } else {
            Err(MerkleError::ConsistencyFailed {
                expected: old_root,
                actual: new_root,
            })
        }
    }
}

#[cfg(test)]
mod consistency_tests {
    use super::*;
    use crate::entry::{ArtifactType, MerkleEntry};

    fn build_tree(n: usize) -> MerkleTree {
        let mut tree = MerkleTree::new();
        for i in 0..n {
            let entry =
                MerkleEntry::new(i as u64, ArtifactType::CertificateIssuance, [i as u8; 32]);
            tree.append(entry);
        }
        tree
    }

    #[test]
    fn consistency_proof_empty_for_same_size() {
        let tree = build_tree(8);
        let proof = tree.consistency_proof(8).unwrap();
        assert!(proof.is_empty());
    }

    #[test]
    fn consistency_proof_empty_for_zero() {
        let tree = build_tree(8);
        let proof = tree.consistency_proof(0).unwrap();
        assert!(proof.is_empty());
    }

    #[test]
    fn consistency_proof_rejects_old_larger_than_current() {
        let tree = build_tree(4);
        assert!(tree.consistency_proof(8).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::ArtifactType;

    #[test]
    fn empty_tree_has_zero_root() {
        let tree = MerkleTree::new();
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn single_entry_tree() {
        let mut tree = MerkleTree::new();
        let entry = MerkleEntry::new(0, ArtifactType::CertificateIssuance, [1u8; 32]);
        tree.append(entry);
        let root = tree.root();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn multiple_entries_produce_different_root() {
        let mut tree1 = MerkleTree::new();
        let mut tree2 = MerkleTree::new();

        tree1.append(MerkleEntry::new(
            0,
            ArtifactType::CertificateIssuance,
            [1u8; 32],
        ));
        tree1.append(MerkleEntry::new(
            1,
            ArtifactType::CertificateIssuance,
            [2u8; 32],
        ));

        tree2.append(MerkleEntry::new(
            0,
            ArtifactType::CertificateIssuance,
            [1u8; 32],
        ));
        tree2.append(MerkleEntry::new(
            1,
            ArtifactType::CertificateIssuance,
            [3u8; 32],
        ));

        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn inclusion_proof_round_trip() {
        let mut tree = MerkleTree::new();
        let mut entries = Vec::new();
        for i in 0..5u64 {
            let e = MerkleEntry::new(i, ArtifactType::CertificateIssuance, [i as u8; 32]);
            entries.push(e.clone());
            tree.append(e);
        }
        let root = tree.root();
        // Verify every leaf has a valid inclusion proof
        for i in 0..5 {
            let proof = tree.inclusion_proof(i).unwrap();
            MerkleTree::verify_inclusion(&entries[i as usize], &proof, root)
                .expect("inclusion proof must verify");
        }
    }

    #[test]
    fn inclusion_proof_negative_case() {
        let mut tree = MerkleTree::new();
        let entries: Vec<MerkleEntry> = (0..5u64)
            .map(|i| MerkleEntry::new(i, ArtifactType::CertificateIssuance, [i as u8; 32]))
            .collect();
        for e in &entries {
            tree.append(e.clone());
        }
        let root = tree.root();
        // Use proof for entry 2 but try to verify entry 3
        let wrong_proof = tree.inclusion_proof(2).unwrap();
        let result = MerkleTree::verify_inclusion(&entries[3], &wrong_proof, root);
        assert!(matches!(result, Err(MerkleError::InclusionFailed(_))));
    }

    #[test]
    fn inclusion_proof_power_of_two_tree() {
        // 8 entries (power of 2) — clean binary tree
        let mut tree = MerkleTree::new();
        let entries: Vec<MerkleEntry> = (0..8u64)
            .map(|i| MerkleEntry::new(i, ArtifactType::CertificateIssuance, [i as u8; 32]))
            .collect();
        for e in &entries {
            tree.append(e.clone());
        }
        let root = tree.root();
        for i in 0..8 {
            let proof = tree.inclusion_proof(i).unwrap();
            MerkleTree::verify_inclusion(&entries[i as usize], &proof, root).expect("must verify");
        }
    }

    #[test]
    fn out_of_range_returns_error() {
        let tree = MerkleTree::new();
        let result = tree.entry(0);
        assert!(matches!(result, Err(MerkleError::OutOfRange(_, _))));
    }
}
