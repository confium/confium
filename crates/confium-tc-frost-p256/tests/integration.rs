//! Integration test: full threshold signing + verification lifecycle.
//!
//! Exercises the public API as a consumer would, including:
//! - Keypair generation
//! - Shamir secret sharing over P-256
//! - Multi-subset Lagrange recovery (different T-of-N selections)
//! - Real ECDSA signing
//! - Real ECDSA verification using p256::ecdsa

use confium_tc_frost_p256::{
    keys::{generate_keypair, public_key_for},
    scalar,
    shamir::{Share, recover_secret, split_secret},
    sign::sign_message,
};
use p256::ecdsa::{Signature, signature::Verifier};

#[test]
fn integration_full_threshold_lifecycle_3_of_5() {
    let keypair = generate_keypair();
    let shares = split_secret(&keypair.secret_scalar, 3, 5);
    assert_eq!(shares.len(), 5);

    let subset: Vec<&Share> = vec![&shares[0], &shares[2], &shares[4]];
    let recovered = recover_secret(&subset).expect("recover from non-contiguous subset");
    assert_eq!(recovered, keypair.secret_scalar);

    let message = b"threshold integration test";
    let signed = sign_message(&keypair, message).expect("sign");

    let vk = keypair.to_verifying_key();
    let sig = Signature::from_der(&signed.der_bytes).expect("parse sig");
    vk.verify(message, &sig).expect("verify must succeed");
}

#[test]
fn integration_threshold_1_of_1() {
    let keypair = generate_keypair();
    let shares = split_secret(&keypair.secret_scalar, 1, 1);
    assert_eq!(shares.len(), 1);

    let subset: Vec<&Share> = vec![&shares[0]];
    let recovered = recover_secret(&subset).expect("recover");
    assert_eq!(recovered, keypair.secret_scalar);
}

#[test]
fn integration_threshold_2_of_3() {
    let keypair = generate_keypair();
    let shares = split_secret(&keypair.secret_scalar, 2, 3);

    // Use any 2 of the 3 shares
    for i in 0..3 {
        let j = (i + 1) % 3;
        let subset: Vec<&Share> = vec![&shares[i], &shares[j]];
        let recovered = recover_secret(&subset).expect("recover");
        assert_eq!(
            recovered, keypair.secret_scalar,
            "subset [{i}, {j}] must recover secret"
        );
    }
}

#[test]
fn integration_all_share_subsets_recover_same_secret() {
    let keypair = generate_keypair();
    let shares = split_secret(&keypair.secret_scalar, 3, 5);

    // All C(5,3) = 10 subsets of size 3 must recover the same secret.
    for i in 0..5 {
        for j in (i + 1)..5 {
            for k in (j + 1)..5 {
                let subset: Vec<&Share> = vec![&shares[i], &shares[j], &shares[k]];
                let recovered = recover_secret(&subset).expect("recover");
                assert_eq!(
                    recovered, keypair.secret_scalar,
                    "subset [{i},{j},{k}] failed"
                );
            }
        }
    }
}

#[test]
fn integration_public_key_derivation_matches_keypair() {
    let keypair = generate_keypair();
    let pk_again = public_key_for(&keypair.secret_scalar);
    assert_eq!(pk_again, keypair.public_key);
}

#[test]
fn integration_scalar_serialization_round_trips() {
    let s = scalar::random_scalar();
    let bytes = scalar::scalar_to_bytes(&s);
    let recovered = scalar::scalar_from_bytes(&bytes).unwrap();
    assert_eq!(s, recovered);
}

#[test]
fn integration_signature_is_distinct_per_message() {
    let keypair = generate_keypair();
    let m1 = b"message one";
    let m2 = b"message two";
    let s1 = sign_message(&keypair, m1).unwrap();
    let s2 = sign_message(&keypair, m2).unwrap();
    assert_ne!(s1.der_bytes, s2.der_bytes, "signatures must differ");
}
