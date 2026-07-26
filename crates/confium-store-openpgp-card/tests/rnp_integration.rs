//! Integration test: real rnp-rs (librnp) round-trip via `RnpOpenpgpCardBackend`.
//!
//! Proves that the rnp-rs binding at `~/src/rnp/rnp-rs` works inside
//! confium's workspace:
//! 1. `cargo build -p confium-store-openpgp-card` resolves the path dep
//! 2. The generated RSA key actually signs and verifies against itself
//! 3. PIN policy is enforced
//!
//! No physical OpenPGP card is needed: the backend models the card as a
//! passphrase-protected rnp keystore, which has the same "key never leaves
//! the device" property as a real YubiKey.

use confium_store_openpgp_card::{
    CardError, OpenpgpCardBackend, OpenpgpSlot, RnpOpenpgpCardBackend,
};
use rnp::{Context, Hash, KeyBuilder, KeyUsage, Algorithm};

const PIN: &str = "12345678";

#[test]
fn sign_verify_round_trip_via_rnp_backend() {
    let mut card = RnpOpenpgpCardBackend::new("YubiKey-Test-001", PIN).unwrap();

    // No PIN yet — must refuse to sign.
    let digest = [0xab; 32];
    match card.sign(&digest) {
        Err(CardError::VerificationRequired(_)) => {}
        other => panic!("expected VerificationRequired, got {other:?}"),
    }

    // Admin verifies → can generate SIG slot key.
    card.verify_admin_pin_session(PIN).unwrap();
    let pub_key = card.generate_keypair(OpenpgpSlot::Signature, "RSA-2048").unwrap();
    assert!(!pub_key.is_empty(), "public key export must be non-empty");

    // User verifies → can sign.
    card.verify_pin_session(PIN).unwrap();
    let signed = card.sign(&digest).unwrap();
    assert!(
        signed.len() > 32,
        "OpenPGP signed message should be larger than the input digest, got {} bytes",
        signed.len()
    );

    // Verify externally against the public key bytes we got back. We use a
    // fresh rnp context for verification — proves the export is a self-
    // contained, parseable public key.
    let verifier = Context::new().unwrap();
    verifier
        .load_keys(
            rnp::context::KeyringFormat::Gpg,
            &pub_key,
            rnp::key::LoadSaveFlags::PUBLIC,
        )
        .expect("public key bytes must be loadable into a fresh rnp context");

    // The verify call itself just needs the signed message; rnp looks up
    // signer keys in the loaded keyring.
    let result = rnp::verify(&verifier, &signed).expect("verify must not error");
    assert!(
        result.any_valid().unwrap(),
        "rnp-rs must accept the signature produced by RnpOpenpgpCardBackend"
    );
}

#[test]
fn factory_reset_clears_session_state() {
    let mut card = RnpOpenpgpCardBackend::new("YubiKey-Test-002", PIN).unwrap();
    card.verify_admin_pin_session(PIN).unwrap();
    card.generate_keypair(OpenpgpSlot::Signature, "RSA-2048").unwrap();
    card.verify_pin_session(PIN).unwrap();

    card.factory_reset().unwrap();

    // After reset, PIN must be required again.
    match card.sign(b"hello") {
        Err(CardError::VerificationRequired(_)) => {}
        other => panic!("expected VerificationRequired after factory_reset, got {other:?}"),
    }
    // And the SIG slot is empty.
    match card.generate_keypair(OpenpgpSlot::Signature, "RSA-2048") {
        // succeeds because we cleared pin_verified but admin is also cleared…
        // we need to re-verify admin first
        Err(CardError::VerificationRequired(_)) => {}
        Ok(_) => panic!("admin must be required after factory_reset"),
        Err(other) => panic!("unexpected error after factory_reset: {other:?}"),
    }
}

#[test]
fn standalone_rnp_smoke_test_for_comparison() {
    // Parallel to the backend test, but uses rnp directly — proves that the
    // crate as a whole (without our wrapper) compiles and links inside
    // confium's workspace.
    let ctx = Context::new().unwrap();
    let key = KeyBuilder::new(Algorithm::Rsa)
        .bits(2048)
        .userid("smoke@test")
        .hash(Hash::Sha256)
        .add_usage(KeyUsage::Sign)
        .build(&ctx)
        .expect("KeyBuilder must succeed inside confium workspace");
    let msg = b"hello from confium + rnp-rs";
    let signed = rnp::sign(&ctx, msg, &key).expect("sign must succeed");
    let result = rnp::verify(&ctx, &signed).expect("verify must succeed");
    assert!(result.any_valid().unwrap());
}