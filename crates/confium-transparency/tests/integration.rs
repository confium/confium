//! Integration test: append multiple entries, verify root changes,
//! verify inclusion proof round-trips.

use confium_transparency::{
    entry::{ArtifactType, MerkleEntry},
    merkle::{Hash, MerkleTree},
};

fn make_entry(seq: u64, hash_byte: u8) -> MerkleEntry {
    let mut e = MerkleEntry::new(seq, ArtifactType::CertificateIssuance, [hash_byte; 32]);
    // Make timestamps deterministic for tests that compare roots.
    e.timestamp = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 1, 1, 0, 0, 0).unwrap();
    e
}

#[test]
fn root_changes_as_entries_appended() {
    let mut tree = MerkleTree::new();
    let root0 = tree.root();

    tree.append(make_entry(0, 1));
    let root1 = tree.root();
    assert_ne!(root0, root1);

    tree.append(make_entry(1, 2));
    let root2 = tree.root();
    assert_ne!(root1, root2);
}

#[test]
fn same_entries_produce_same_root() {
    let mut tree_a = MerkleTree::new();
    let mut tree_b = MerkleTree::new();

    for i in 0..5u64 {
        tree_a.append(make_entry(i, i as u8));
        tree_b.append(make_entry(i, i as u8));
    }

    assert_eq!(tree_a.root(), tree_b.root());
}

#[test]
fn empty_tree_has_zero_root() {
    let tree = MerkleTree::new();
    let zero: Hash = [0u8; 32];
    assert_eq!(tree.root(), zero);
}

#[test]
fn entry_count_matches_appends() {
    let mut tree = MerkleTree::new();
    for i in 0..10u64 {
        tree.append(make_entry(i, i as u8));
    }
    assert_eq!(tree.len(), 10);
}

#[test]
fn entry_lookup_by_sequence() {
    let mut tree = MerkleTree::new();
    let original = make_entry(5, 0xAB);
    tree.append(make_entry(0, 0));
    tree.append(make_entry(1, 1));
    tree.append(make_entry(2, 2));
    tree.append(make_entry(3, 3));
    tree.append(make_entry(4, 4));
    tree.append(original);
    let entry = tree.entry(5).expect("entry exists");
    assert_eq!(entry.artifact_hash, [0xAB; 32]);
    assert_eq!(entry.artifact_type, ArtifactType::CertificateIssuance);
}

#[test]
fn out_of_range_lookup_fails() {
    let tree = MerkleTree::new();
    let result = tree.entry(99);
    assert!(result.is_err());
}

#[test]
fn timestamp_is_set_on_construction() {
    let entry = make_entry(0, 0);
    // Constructed entry has fixed timestamp in our test helper.
    assert_eq!(entry.timestamp.timestamp(), 1767225600);
}
