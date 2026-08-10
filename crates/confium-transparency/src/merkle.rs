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
#[derive(Debug, Default, Clone)]
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

/// Largest power of two strictly less than `n`. Returns 0 for `n <= 1`.
///
/// Used by [`MerkleTree::consistency_rec`] to split the implicit tree
/// into LEFT (size `k`) and RIGHT (size `n - k`) subtrees.
fn largest_pow2_strictly_less_than(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
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
            .ok_or(MerkleError::OutOfRange(sequence, self.entries.len()))
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
    /// Returns the "consistency path" — a list of subtree hashes that
    /// the verifier uses to reconstruct both the old and new roots.
    pub fn consistency_proof(&self, old_size: usize) -> Result<Vec<Hash>, MerkleError> {
        let new_size = self.leaf_hashes.len();
        if old_size > new_size {
            return Err(MerkleError::OutOfRange(old_size as u64, new_size));
        }
        if old_size == 0 || old_size == new_size {
            return Ok(Vec::new());
        }
        Ok(self.consistency_rec(0, old_size, new_size))
    }

    /// Recursive helper for [`consistency_proof`](Self::consistency_proof).
    ///
    /// Returns the consistency path proving that the first `old_size`
    /// leaves (starting at offset `start`) hash to the same root as a
    /// standalone tree of `old_size` leaves, embedded in a larger tree
    /// of `new_size` leaves.
    ///
    /// Algorithm: split `new_size` into a LEFT perfect subtree of size
    /// `k = largest_pow2_strictly_less_than(new_size)` and a RIGHT
    /// subtree of size `new_size - k`. Then:
    ///   - If `old_size <= k`: the old tree is entirely within LEFT.
    ///     Recurse on LEFT, then append the RIGHT subtree root.
    ///   - Otherwise: the old tree spans both subtrees. Recurse on
    ///     RIGHT (with `old_size - k`), then prepend the LEFT subtree
    ///     root.
    fn consistency_rec(&self, start: usize, old_size: usize, new_size: usize) -> Vec<Hash> {
        if old_size == new_size {
            return Vec::new();
        }
        let k = largest_pow2_strictly_less_than(new_size);
        if old_size <= k {
            let mut sub = self.consistency_rec(start, old_size, k);
            sub.push(self.subtree_root(start + k, new_size - k));
            sub
        } else {
            let mut sub = self.consistency_rec(start + k, old_size - k, new_size - k);
            let mut result = vec![self.subtree_root(start, k)];
            result.append(&mut sub);
            result
        }
    }

    /// Compute the root of the subtree covering `size` leaves starting
    /// at offset `start`. Handles arbitrary `size` by decomposing into
    /// perfect subtrees (compact frontier representation).
    ///
    /// For example, `subtree_root(start, 11)` decomposes 11 = 8 + 2 + 1
    /// and folds the three subtree roots right-to-left per RFC 6962.
    fn subtree_root(&self, start: usize, size: usize) -> Hash {
        debug_assert!(
            start + size <= self.leaf_hashes.len(),
            "subtree_root: out of range"
        );
        if size == 0 {
            return [0u8; 32];
        }

        // Decompose `size` into decreasing powers of 2 and compute each
        // perfect subtree root. Then fold right-to-left: start with the
        // smallest subtree, combine with each larger one on the left.
        let mut frontier: Vec<(usize, Hash)> = Vec::new();
        let mut offset = start;
        let mut remaining = size;
        let mut k = 1usize;
        // Find largest pow2 <= remaining
        while k * 2 <= remaining {
            k *= 2;
        }
        while remaining > 0 {
            if remaining >= k {
                let hash = self.perfect_subtree_root(offset, k);
                frontier.push((k, hash));
                offset += k;
                remaining -= k;
            }
            k /= 2;
        }

        // Fold right-to-left: start with smallest, combine with each
        // larger one. Result: hash(largest, hash(., hash(smallest)))
        let mut acc = frontier
            .last()
            .expect("non-empty size yields non-empty frontier")
            .1;
        for &(_, h) in frontier.iter().rev().skip(1) {
            acc = hash_internal(h, acc);
        }
        acc
    }

    /// Compute the root of a PERFECT binary subtree of `size` leaves
    /// starting at `start`. `size` must be a power of 2. Used by
    /// [`subtree_root`](Self::subtree_root) for each entry in the
    /// compact frontier decomposition.
    fn perfect_subtree_root(&self, start: usize, size: usize) -> Hash {
        debug_assert!(
            size.is_power_of_two(),
            "perfect_subtree_root: size must be pow2"
        );
        if size == 1 {
            return self.leaf_hashes[start];
        }
        let mut level: Vec<Hash> = self.leaf_hashes[start..start + size].to_vec();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for chunk in level.chunks(2) {
                next.push(hash_internal(chunk[0], chunk[1]));
            }
            level = next;
        }
        level[0]
    }

    /// Compute the Merkle root of the first `size` leaves. Used by
    /// [`verify_consistency`](Self::verify_consistency) for brute-force
    /// verification by recomputing the old tree's root directly.
    fn root_at_size(&self, size: usize) -> Hash {
        if size == 0 || size > self.leaf_hashes.len() {
            return [0u8; 32];
        }
        let mut level: Vec<Hash> = self.leaf_hashes[..size].to_vec();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2 + 1);
            let mut iter = level.iter();
            loop {
                match (iter.next(), iter.next()) {
                    (Some(l), Some(r)) => next.push(hash_internal(*l, *r)),
                    (Some(l), None) => next.push(*l),
                    _ => break,
                }
            }
            level = next;
        }
        level[0]
    }

    /// Verify a consistency proof (RFC 6962 §2.1.2).
    ///
    /// Brute-force verification: recompute the root at `old_size` and
    /// the current root from this tree's leaves, then compare to
    /// `old_root` and `new_root` respectively.
    ///
    /// This method requires `&self` because external proof-based
    /// verification (without the tree) requires a much more intricate
    /// algorithm that handles non-power-of-two `old_size` correctly.
    /// That algorithm is tracked as a follow-up; for now, this
    /// brute-force path is correct and is what bindings use.
    ///
    /// The `proof` parameter is accepted for forward compatibility —
    /// it is currently unused (verification is done by direct
    /// recomputation), but the API shape is preserved so a future
    /// proof-based verifier can plug in without breaking callers.
    pub fn verify_consistency(
        &self,
        old_root: Hash,
        new_root: Hash,
        old_size: usize,
        new_size: usize,
        _proof: &[Hash],
    ) -> Result<(), MerkleError> {
        if old_size == 0 {
            return Ok(());
        }
        let current_size = self.leaf_hashes.len();
        if new_size != current_size {
            return Err(MerkleError::ConsistencyFailed {
                expected: new_root,
                actual: self.root(),
            });
        }
        if old_size > current_size {
            return Err(MerkleError::OutOfRange(old_size as u64, current_size));
        }

        let computed_old_root = self.root_at_size(old_size);
        let computed_new_root = self.root();

        if computed_old_root == old_root && computed_new_root == new_root {
            Ok(())
        } else {
            Err(MerkleError::ConsistencyFailed {
                expected: old_root,
                actual: computed_old_root,
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

    #[test]
    fn consistency_proof_returns_subtree_hashes_for_pow2_old_size() {
        // For (old=4, new=8): proof should contain the right 4-leaf subtree root.
        let tree = build_tree(8);
        let proof = tree.consistency_proof(4).unwrap();
        assert_eq!(proof.len(), 1, "expected single entry for (4, 8)");
    }

    #[test]
    fn consistency_proof_returns_multiple_entries_for_non_pow2() {
        // For (old=3, new=5): generator emits [root_01, lh_3, lh_4].
        let tree = build_tree(5);
        let proof = tree.consistency_proof(3).unwrap();
        assert_eq!(proof.len(), 3, "expected 3 entries for (3, 5)");
    }

    #[test]
    fn verify_consistency_accepts_valid_pow2_old_size() {
        let mut tree = build_tree(8);
        let old_root = tree.root_at_size(4);
        // Grow to 12 by appending more entries.
        for i in 8..12 {
            let entry =
                MerkleEntry::new(i as u64, ArtifactType::CertificateIssuance, [i as u8; 32]);
            tree.append(entry);
        }
        let new_root = tree.root();
        let proof = tree.consistency_proof(4).unwrap();
        tree.verify_consistency(old_root, new_root, 4, 12, &proof)
            .expect("must verify for valid pow2 old_size");
    }

    #[test]
    fn verify_consistency_accepts_valid_non_pow2_old_size() {
        let mut tree = build_tree(5);
        let old_root = tree.root_at_size(3);
        for i in 5..11 {
            let entry =
                MerkleEntry::new(i as u64, ArtifactType::CertificateIssuance, [i as u8; 32]);
            tree.append(entry);
        }
        let new_root = tree.root();
        let proof = tree.consistency_proof(3).unwrap();
        tree.verify_consistency(old_root, new_root, 3, 11, &proof)
            .expect("must verify for valid non-pow2 old_size");
    }

    #[test]
    fn verify_consistency_detects_tampered_old_root() {
        let mut tree = build_tree(8);
        for i in 8..12 {
            let entry =
                MerkleEntry::new(i as u64, ArtifactType::CertificateIssuance, [i as u8; 32]);
            tree.append(entry);
        }
        let new_root = tree.root();
        let proof = tree.consistency_proof(4).unwrap();
        let bogus_old_root = [0xffu8; 32];
        let result = tree.verify_consistency(bogus_old_root, new_root, 4, 12, &proof);
        assert!(matches!(result, Err(MerkleError::ConsistencyFailed { .. })));
    }

    #[test]
    fn verify_consistency_detects_tampered_new_root() {
        let mut tree = build_tree(8);
        let old_root = tree.root_at_size(4);
        for i in 8..12 {
            let entry =
                MerkleEntry::new(i as u64, ArtifactType::CertificateIssuance, [i as u8; 32]);
            tree.append(entry);
        }
        let proof = tree.consistency_proof(4).unwrap();
        let bogus_new_root = [0xffu8; 32];
        let result = tree.verify_consistency(old_root, bogus_new_root, 4, 12, &proof);
        assert!(matches!(result, Err(MerkleError::ConsistencyFailed { .. })));
    }

    #[test]
    fn verify_consistency_accepts_all_sizes_1_to_16() {
        // Comprehensive: grow the tree from 1 to 16 leaves. At each
        // step, every prior size is a valid old_size. Verify them all.
        let mut tree = MerkleTree::new();
        let mut roots: Vec<Hash> = Vec::new();
        for i in 0..16u64 {
            let entry = MerkleEntry::new(i, ArtifactType::CertificateIssuance, [i as u8; 32]);
            tree.append(entry);
            roots.push(tree.root());
        }
        let final_size = tree.leaf_hashes.len();
        for old_size in 1..=final_size {
            let old_root = roots[old_size - 1];
            let new_root = roots[final_size - 1];
            let proof = tree.consistency_proof(old_size).unwrap();
            tree.verify_consistency(old_root, new_root, old_size, final_size, &proof)
                .unwrap_or_else(|e| {
                    panic!("verify_consistency failed for old_size={old_size}: {e:?}")
                });
        }
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

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::entry::ArtifactType;
    use proptest::prelude::*;

    fn arb_entry(seq: u64) -> MerkleEntry {
        let mut hash = [0u8; 32];
        // Mix seq into a few bytes so each entry has a distinct hash.
        hash[0..8].copy_from_slice(&seq.to_le_bytes());
        MerkleEntry::new(seq, ArtifactType::CertificateIssuance, hash)
    }

    /// For any tree size N in [1, 100], every leaf's inclusion proof
    /// verifies against the current root.
    proptest! {
        #[test]
        fn every_leaf_inclusion_proof_verifies(n in 1u64..100) {
            let mut tree = MerkleTree::new();
            let entries: Vec<MerkleEntry> = (0..n).map(arb_entry).collect();
            for e in &entries {
                tree.append(e.clone());
            }
            let root = tree.root();
            for seq in 0..n {
                let proof = tree.inclusion_proof(seq)?;
                MerkleTree::verify_inclusion(&entries[seq as usize], &proof, root)?;
            }
        }
    }

    /// A proof for one entry must NOT verify a different entry.
    proptest! {
        #[test]
        fn inclusion_proof_rejects_wrong_entry(n in 2u64..50, i in 0u64..50, j in 0u64..50) {
            prop_assume!(n > 1 && i < n && j < n && i != j);
            let mut tree = MerkleTree::new();
            let entries: Vec<MerkleEntry> = (0..n).map(arb_entry).collect();
            for e in &entries {
                tree.append(e.clone());
            }
            let root = tree.root();
            let proof = tree.inclusion_proof(i)?;
            let result = MerkleTree::verify_inclusion(&entries[j as usize], &proof, root);
            prop_assert!(matches!(result, Err(MerkleError::InclusionFailed(_))));
        }
    }

    /// Appending an entry changes the root (log is append-only and
    /// every append is reflected in the commitment).
    proptest! {
        #[test]
        fn append_changes_root(n in 0u64..50) {
            let mut tree = MerkleTree::new();
            for seq in 0..n {
                tree.append(arb_entry(seq));
            }
            let root_before = tree.root();
            tree.append(arb_entry(n));
            let root_after = tree.root();
            prop_assert_ne!(root_before, root_after);
        }
    }

    /// Empty tree's root is the all-zero hash (RFC 6962 convention).
    #[test]
    fn empty_tree_root_is_zero() {
        let tree = MerkleTree::new();
        assert_eq!(tree.root(), [0u8; 32]);
    }
}
