//! Cross-crate integration test: composite signature → transparency
//! log → verify both the signature AND its inclusion proof.
//!
//! Exercises two crates in sequence:
//! 1. `confium-composite` — build + verify an Ed25519 composite.
//! 2. `confium-transparency` — anchor the composite as a log entry
//!    and prove its inclusion.
//!
//! This simulates the "PQ migration transparency" use case: a
//! composite signature is anchored so verifiers can later prove
//! which signature was issued under which algorithm pair.

#![cfg(not(target_arch = "wasm32"))]

use confium_composite::{CompositeSignature, ED25519, build_ed25519_component, ed25519_verifier};
use confium_transparency::{
    MerkleTree,
    entry::{ArtifactType, MerkleEntry},
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

#[test]
fn composite_signature_anchors_into_transparency_log() {
    let signing = SigningKey::generate(&mut OsRng);
    let message = b"cross-crate: composite sig + log";
    let component = build_ed25519_component(&signing, message).expect("build component");
    let composite = CompositeSignature::new(vec![component]);

    // Verify the composite standalone.
    let result = composite
        .verify(message, |alg, pk, msg, sig| {
            if alg == ED25519 {
                ed25519_verifier(alg, pk, msg, sig)
            } else {
                Err(format!("unknown algorithm: {alg}"))
            }
        })
        .expect("verify");
    assert!(result.all_verified);

    // Anchor the composite JSON encoding in the log.
    let composite_json = serde_json::to_vec(&composite).expect("serialize");
    let mut h = Sha256::new();
    h.update(&composite_json);
    let artifact_hash = {
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    };

    let mut tree = MerkleTree::new();
    let entry = MerkleEntry::new(0, ArtifactType::ThresholdSignature, artifact_hash);
    let seq = tree.append(entry);
    let root = tree.root();
    let proof = tree.inclusion_proof(seq).expect("proof");

    // Verify the inclusion proof.
    let entry_ref = tree.entry(seq).expect("entry");
    MerkleTree::verify_inclusion(entry_ref, &proof, root).expect("inclusion verifies");

    // Re-parse the anchored composite and re-verify the signature —
    // the on-the-wire format round-trips through the log.
    let reparsed: CompositeSignature = serde_json::from_slice(&composite_json).expect("parse");
    let result2 = reparsed
        .verify(message, |alg, pk, msg, sig| {
            if alg == ED25519 {
                ed25519_verifier(alg, pk, msg, sig)
            } else {
                Err(format!("unknown algorithm: {alg}"))
            }
        })
        .expect("verify2");
    assert!(result2.all_verified);
}
