//! Property-based tests for the transparency log Merkle tree.

use crate::entry::{ArtifactType, MerkleEntry};
use crate::merkle::MerkleTree;
use proptest::prelude::*;

fn make_entry(sequence: u64, hash_byte: u8) -> MerkleEntry {
    MerkleEntry::new(sequence, ArtifactType::ThresholdSignature, [hash_byte; 32])
}

fn build_tree(entries: &[u8]) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for (i, &b) in entries.iter().enumerate() {
        tree.append(make_entry(i as u64, b));
    }
    tree
}

proptest! {
    #[test]
    fn prop_size_equals_entry_count(n in 0u64..100u64) {
        let tree = build_tree(&(0..n as u8).collect::<Vec<_>>());
        prop_assert_eq!(tree.len(), n as usize);
    }
}

proptest! {
    #[test]
    fn prop_root_deterministic(entries in prop::collection::vec(any::<u8>(), 1..50usize)) {
        let shared: Vec<MerkleEntry> = entries.iter().enumerate()
            .map(|(i, &b)| make_entry(i as u64, b))
            .collect();
        let mut tree_a = MerkleTree::new();
        let mut tree_b = MerkleTree::new();
        for e in &shared {
            tree_a.append(e.clone());
            tree_b.append(e.clone());
        }
        prop_assert_eq!(tree_a.root(), tree_b.root());
    }
}

proptest! {
    #[test]
    fn prop_empty_root_is_zero(_dummy in 0u8..1u8) {
        let tree = MerkleTree::new();
        prop_assert_eq!(tree.root(), [0u8; 32]);
    }
}

proptest! {
    #[test]
    fn prop_inclusion_proof_always_valid(
        entries in prop::collection::vec(any::<u8>(), 2..50usize),
        seq_idx in 0usize..48usize,
    ) {
        prop_assume!(seq_idx < entries.len());
        let tree = build_tree(&entries);
        let seq = seq_idx as u64;
        let entry = tree.entry(seq).unwrap().clone();
        let proof = tree.inclusion_proof(seq).unwrap();
        let root = tree.root();
        prop_assert!(MerkleTree::verify_inclusion(&entry, &proof, root).is_ok());
    }
}

proptest! {
    #[test]
    fn prop_forged_proof_fails(
        entries in prop::collection::vec(any::<u8>(), 2..50usize),
        seq_idx in 0usize..48usize,
        wrong_byte in any::<u8>(),
    ) {
        prop_assume!(seq_idx < entries.len());
        prop_assume!(wrong_byte != entries[seq_idx]);
        let tree = build_tree(&entries);
        let seq = seq_idx as u64;
        let proof = tree.inclusion_proof(seq).unwrap();
        let root = tree.root();
        let mut wrong_entry = tree.entry(seq).unwrap().clone();
        wrong_entry.artifact_hash = [wrong_byte; 32];
        let result = MerkleTree::verify_inclusion(&wrong_entry, &proof, root);
        prop_assert!(result.is_err(), "forged proof should fail");
    }
}

proptest! {
    #[test]
    fn prop_append_changes_root(entries in prop::collection::vec(any::<u8>(), 1..40usize)) {
        let mut tree = build_tree(&entries);
        let root_before = tree.root();
        tree.append(make_entry(entries.len() as u64, 0xAA));
        prop_assert_ne!(root_before, tree.root());
    }
}
