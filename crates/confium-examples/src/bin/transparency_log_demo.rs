//! Transparency log demonstration: append entries, compute root, verify inclusion.
//!
//! Shows the real RFC 6962 inclusion proof verifier in `confium-transparency`:
//!
//! 1. Append 5 entries to the Merkle tree
//! 2. Compute the tree root
//! 3. Generate inclusion proofs for every leaf
//! 4. Verify each proof against the root
//!
//! Run with: `cargo run --example transparency_log_demo`

use chrono::TimeZone;
use confium_transparency::{
    entry::{ArtifactType, MerkleEntry},
    merkle::MerkleTree,
};

fn fixed_entry(seq: u64, hash_byte: u8) -> MerkleEntry {
    let mut e = MerkleEntry::new(seq, ArtifactType::CertificateIssuance, [hash_byte; 32]);
    e.timestamp = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    e
}

fn main() {
    println!("=== Confium Transparency Log Demo (RFC 6962 inclusion proofs) ===\n");

    // Build tree
    let mut tree = MerkleTree::new();
    println!("Appending 5 entries...");
    let entries: Vec<MerkleEntry> = (0..5u64).map(|i| fixed_entry(i, i as u8 + 1)).collect();
    for e in &entries {
        tree.append(e.clone());
    }
    println!("  Tree has {} entries.\n", tree.len());

    // Compute root
    let root = tree.root();
    println!("Tree root: {}\n", hex::encode(root));

    // Verify every leaf's inclusion proof
    println!("Verifying inclusion proofs for every leaf:");
    for i in 0..5u64 {
        let proof = tree.inclusion_proof(i).unwrap();
        MerkleTree::verify_inclusion(&entries[i as usize], &proof, root)
            .expect("inclusion proof must verify");
        println!("  Leaf {}: PROOF VALID ({} steps)", i, proof.steps.len());
    }
    println!();

    // Negative case: use leaf 2's proof to "verify" leaf 3 — must fail
    println!("Negative case: using leaf 2's proof to verify leaf 3...");
    let wrong_proof = tree.inclusion_proof(2).unwrap();
    let result = MerkleTree::verify_inclusion(&entries[3], &wrong_proof, root);
    assert!(result.is_err(), "wrong-leaf verification must fail");
    println!("  Correctly REJECTED.\n");

    println!("=== Demo complete. RFC 6962 inclusion proof verifier working. ===");
}
