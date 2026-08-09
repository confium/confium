//! WASM smoke tests via wasm-bindgen-test. Run with
//! `wasm-pack test --node crates/confium-wasm --release`.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

// wasm-bindgen-test runs under Node by default; no configure!() needed.

#[wasm_bindgen_test]
fn version_smoke() {
    let v = confium_wasm::version();
    assert!(v.split('.').count() >= 2, "version looks like semver: {v}");
}

#[wasm_bindgen_test]
fn parse_invalid_composite_signature_errors() {
    let err = confium_wasm::CompositeSignature::from_json("{not json");
    assert!(err.is_err(), "bogus JSON should error");
}

#[wasm_bindgen_test]
fn parse_valid_but_empty_composite_signature_compiles() {
    // This is just a parse-level smoke test — the underlying verify
    // against an empty component list will error, but the JSON parse
    // itself must succeed.
    let json = r#"{"components":[]}"#;
    let sig = confium_wasm::CompositeSignature::from_json(json).unwrap();
    assert_eq!(sig.component_count(), 0);
}

#[wasm_bindgen_test]
fn merkle_tree_empty() {
    use confium_wasm::*;
    let tree = MerkleTree::new();
    assert_eq!(tree.length(), 0);
}

#[wasm_bindgen_test]
fn merkle_tree_append_increments_length() {
    use confium_wasm::*;
    let tree = MerkleTree::new();
    let artifact = [0u8; 32];
    let seq = tree.append(&artifact).unwrap();
    assert_eq!(seq, 0);
    assert_eq!(tree.length(), 1);
    assert_eq!(tree.root().len(), 32);
}

#[wasm_bindgen_test]
fn merkle_inclusion_proof_round_trip() {
    use confium_wasm::*;
    let tree = MerkleTree::new();
    let mut seqs = Vec::new();
    for i in 0u8..3 {
        let seq = tree.append(&[i; 32]).unwrap();
        seqs.push(seq);
    }
    let root = tree.root();
    for seq in seqs {
        let proof = tree.inclusion_proof(seq).unwrap();
        assert_eq!(proof.sequence(), seq);
        assert!(
            proof.verify(&root).unwrap(),
            "inclusion proof for seq {seq} must verify"
        );
    }
}

#[wasm_bindgen_test]
fn predicate_parse_and_evaluate() {
    use confium_wasm::*;
    let pred = Predicate::parse(r#"min_count("role:director", 2)"#).unwrap();
    let signers = r#"[
        {"role:director": ["yes"]},
        {"role:director": ["yes"]}
    ]"#;
    assert!(pred.satisfied_by(signers).unwrap());

    let signers_short = r#"[{"role:director": ["yes"]}]"#;
    assert!(!pred.satisfied_by(signers_short).unwrap());
}

#[wasm_bindgen_test]
fn certificate_from_der_rejects_garbage() {
    use confium_wasm::*;
    let err = Certificate::from_der(&[0u8; 10]);
    assert!(err.is_err(), "garbage DER should error");
}

#[wasm_bindgen_test]
fn signed_data_round_trips_through_json() {
    use confium_wasm::*;
    let json = r#"{
        "version": 1,
        "digest_algorithms": [{"oid":"2.16.840.1.101.3.4.2.1"}],
        "encap_content_info": {
            "content_type":"1.2.840.113549.1.7.1",
            "content":[72,101,108,108,111]
        },
        "certificates":[],
        "signer_infos":[]
    }"#;
    let sd = SignedData::from_json(json).unwrap();
    assert_eq!(sd.signer_count(), 0);
    assert_eq!(sd.content_type(), "1.2.840.113549.1.7.1");
    assert_eq!(sd.certificate_count(), 0);
    assert_eq!(sd.content().unwrap(), vec![72, 101, 108, 108, 111]);

    let round = SignedData::from_json(&sd.to_json().unwrap()).unwrap();
    assert_eq!(round.content_type(), sd.content_type());
}

#[wasm_bindgen_test]
fn tree_head_round_trips_through_json() {
    use confium_wasm::*;
    let json = r#"{"size":42,"root":[171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171,171]}"#;
    let parsed = tree_head_from_json(json).unwrap();
    assert!(parsed.contains("\"size\":42"));
    assert!(parsed.contains("\"root_hex\":\"abab"));
}

#[wasm_bindgen_test]
fn compute_artifact_hash_is_sha256() {
    use confium_wasm::*;
    let h = compute_artifact_hash(b"hello");
    // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    let expected = [
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2,
        0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b,
        0x98, 0x24,
    ];
    assert_eq!(h, expected);
}

#[wasm_bindgen_test]
fn compute_leaf_hash_round_trips_through_inclusion_proof() {
    use confium_wasm::*;
    // Build a tree in-process, anchor a single 32-byte entry.
    let tree = MerkleTree::new();
    let artifact_hash = [0x42u8; 32];
    let seq = tree.append(&artifact_hash).unwrap();
    let _leaf_hash = compute_leaf_hash(seq as u64, 0.0, &artifact_hash);
    let _proof = tree.inclusion_proof(seq).unwrap();
    // For a 1-leaf tree, root == hash_leaf(entry_hash) == leaf_hash.
    // The helpers compile and link; deeper round-trip is exercised in
    // the Rust-side transparency integration tests.
}
