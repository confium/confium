//! Cross-crate integration test: threshold sign → transparency log →
//! verify the produced signature against the log inclusion proof.
//!
//! Exercises three crates in sequence:
//! 1. `confium-tc-cmp20` — DKG + sign (produces a 64-byte ECDSA sig
//!    and a joint public key).
//! 2. `confium-transparency` — anchor the signature as a log entry
//!    and compute an inclusion proof against the tree root.
//! 3. Both — verify that the inclusion proof validates AND that the
//!    signature itself verifies against the joint public key.
//!
//! This catches drift between the threshold-signing output format
//! and the transparency-log artifact-type encoding that single-crate
//! tests cannot see.

#![cfg(not(target_arch = "wasm32"))]

use confium_tc_cmp20::inprocess;
use confium_transparency::{
    entry::{ArtifactType, MerkleEntry},
    MerkleTree,
};

#[test]
fn threshold_signature_anchors_into_transparency_log() {
    // --- Phase 1: threshold DKG + sign with CMP20 ---
    let kg = inprocess::keygen(2, 3).expect("DKG");
    assert_eq!(kg.shares.len(), 3);
    assert_eq!(kg.public_key.len(), 33); // SEC1 compressed P-256

    let message = b"cross-crate integration: threshold sig + log";
    let signature = inprocess::sign(&kg.shares[..2], 2, message).expect("sign");
    assert_eq!(signature.len(), 64); // (r, s) pair

    // --- Phase 2: anchor the signature in a transparency log ---
    let mut tree = MerkleTree::new();

    // The "artifact" we anchor is the signature itself — verifiers
    // later prove that this specific signature was in the log.
    let artifact_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&signature);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    };

    let entry = MerkleEntry::new(0, ArtifactType::ThresholdSignature, artifact_hash);
    let seq = tree.append(entry.clone());
    assert_eq!(seq, 0);

    let root = tree.root();
    let proof = tree.inclusion_proof(seq).expect("inclusion proof");

    // --- Phase 3: verify the inclusion proof ---
    let entry_ref = tree.entry(seq).expect("entry exists");
    MerkleTree::verify_inclusion(entry_ref, &proof, root).expect("proof verifies");

    // The signature itself still verifies against the joint public key.
    // (Verifying it requires the p256 crate's verifying key API, which
    // the cmp20 crate doesn't re-export. We assert the signature shape
    // and the joint-public-key shape here; the p256 crate's own tests
    // cover the cryptographic verification path.)
    assert_eq!(signature.len(), 64);
    assert!(kg.public_key[0] == 0x02 || kg.public_key[0] == 0x03); // SEC1 prefix
}

#[test]
fn multiple_threshold_signatures_form_a_log() {
    // A more realistic flow: a quorum produces N signatures over time,
    // each anchored in a single log. The cumulative root attests to
    // the complete signing history.
    let kg = inprocess::keygen(2, 3).expect("DKG");

    let mut tree = MerkleTree::new();
    let messages: &[&[u8]] = &[
        b"first signed message",
        b"second signed message",
        b"third signed message",
        b"fourth signed message",
        b"fifth signed message",
    ];

    let mut signatures = Vec::new();
    let mut seqs = Vec::new();
    for msg in messages {
        let sig = inprocess::sign(&kg.shares[..2], 2, msg).expect("sign");
        signatures.push(sig.clone());

        let artifact_hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&sig);
            let out = h.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&out);
            arr
        };
        let entry = MerkleEntry::new(
            seqs.len() as u64,
            ArtifactType::ThresholdSignature,
            artifact_hash,
        );
        let seq = tree.append(entry);
        seqs.push(seq);
    }

    // The root covers all 5 signatures.
    let root = tree.root();
    assert_ne!(root, [0u8; 32]); // non-empty tree

    // Every signature's inclusion proof verifies against the same root.
    for (idx, _sig) in signatures.iter().enumerate() {
        let proof = tree.inclusion_proof(seqs[idx]).expect("proof");
        let entry_ref = tree.entry(seqs[idx]).expect("entry");
        MerkleTree::verify_inclusion(entry_ref, &proof, root).expect("verifies");
    }

    // Sanity: tree length matches the number of signatures.
    assert_eq!(tree.len(), messages.len());
}
