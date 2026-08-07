//! Property-based tests for composite signature verification.

use crate::{
    ComponentSignature, CompositeSignature, ED25519, build_ed25519_component,
    ed25519_verifier,
};
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use rand_core::OsRng;

fn make_valid_composite(message: &[u8]) -> (SigningKey, CompositeSignature) {
    let signing = SigningKey::generate(&mut OsRng);
    let component = build_ed25519_component(&signing, message).expect("build");
    let composite = CompositeSignature::new(vec![component]);
    (signing, composite)
}

proptest! {
    /// Verifying the same valid signature N times always succeeds.
    #[test]
    fn prop_verify_deterministic(msg in prop::collection::vec(any::<u8>(), 1..256)) {
        let (_, composite) = make_valid_composite(&msg);
        for _ in 0..5 {
            let result = composite.verify(&msg, |alg, pk, m, sig| {
                ed25519_verifier(alg, pk, m, sig)
            }).unwrap();
            prop_assert!(result.all_verified);
        }
    }

    /// Flipping any bit in the signature causes verification to fail.
    #[test]
    fn prop_tampered_signature_fails(
        msg in prop::collection::vec(any::<u8>(), 1..256),
        byte_idx in 0usize..64,
        bit_idx in 0u8..8,
    ) {
        let (_, mut composite) = make_valid_composite(&msg);
        let sig_len = composite.components[0].signature.len();
        prop_assume!(byte_idx < sig_len);
        composite.components[0].signature[byte_idx] ^= 1 << bit_idx;

        let result = composite.verify(&msg, |alg, pk, m, sig| {
            ed25519_verifier(alg, pk, m, sig)
        }).unwrap();
        prop_assert!(!result.all_verified, "tampered sig should not verify");
    }

    /// Flipping any bit in the message causes verification to fail.
    #[test]
    fn prop_tampered_message_fails(
        msg in prop::collection::vec(any::<u8>(), 2..256),
        byte_idx in 0usize..255,
        bit_idx in 0u8..8,
    ) {
        prop_assume!(byte_idx < msg.len());
        let (_, composite) = make_valid_composite(&msg);
        let mut tampered = msg.clone();
        tampered[byte_idx] ^= 1 << bit_idx;

        let result = composite.verify(&tampered, |alg, pk, m, sig| {
            ed25519_verifier(alg, pk, m, sig)
        }).unwrap();
        prop_assert!(!result.all_verified, "tampered msg should not verify");
    }

    /// Flipping any bit in the public key causes verification to fail.
    #[test]
    fn prop_tampered_pubkey_fails(
        msg in prop::collection::vec(any::<u8>(), 1..256),
        byte_idx in 0usize..32,
        bit_idx in 0u8..8,
    ) {
        let (_, mut composite) = make_valid_composite(&msg);
        let pk_len = composite.components[0].public_key.len();
        prop_assume!(byte_idx < pk_len);
        composite.components[0].public_key[byte_idx] ^= 1 << bit_idx;

        let result = composite.verify(&msg, |alg, pk, m, sig| {
            ed25519_verifier(alg, pk, m, sig)
        }).unwrap();
        prop_assert!(!result.all_verified, "tampered pubkey should not verify");
    }

    /// Removing the only component causes Empty error.
    #[test]
    fn prop_empty_composite_errors(msg in prop::collection::vec(any::<u8>(), 1..64)) {
        let composite = CompositeSignature::new(vec![]);
        let result = composite.verify(&msg, |_, _, _, _| Ok(()));
        prop_assert!(result.is_err());
    }

    /// Component count is always accurate.
    #[test]
    fn prop_component_count(n in 1usize..10) {
        let components: Vec<ComponentSignature> = (0..n).map(|i| {
            let signing = SigningKey::generate(&mut OsRng);
            let mut c = build_ed25519_component(&signing, b"msg").unwrap();
            c.algorithm = format!("{}-{}", ED25519, i);
            c
        }).collect();
        let composite = CompositeSignature::new(components);
        prop_assert_eq!(composite.component_count(), n);
    }

    /// Algorithms list has correct length.
    #[test]
    fn prop_algorithms_list(n in 1usize..8) {
        let mut components = Vec::new();
        for i in 0..n {
            let signing = SigningKey::generate(&mut OsRng);
            let mut c = build_ed25519_component(&signing, b"msg").unwrap();
            c.algorithm = format!("alg{}", i);
            components.push(c);
        }
        let composite = CompositeSignature::new(components);
        let algs = composite.algorithms();
        prop_assert_eq!(algs.len(), n);
    }
}
