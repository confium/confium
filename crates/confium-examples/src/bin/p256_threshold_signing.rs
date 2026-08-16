//! Mode 1 demonstration: 3-of-5 threshold signing with real P-256 cryptography.
//!
//! This example demonstrates the real cryptographic primitives in
//! `confium-tc-frost-p256`:
//!
//! 1. Generate a P-256 keypair
//! 2. Split the secret into 5 shares with threshold T=3 (real Shamir over P-256)
//! 3. Recover the secret from any 3 shares (real Lagrange interpolation)
//! 4. Sign a message with the keypair (real P-256 ECDSA)
//! 5. Verify the signature under the public key
//!
//! Run with: `cargo run --example p256_threshold_signing`

use confium_tc_frost_p256::{keys, shamir, sign};
use p256::ecdsa::{Signature, signature::Verifier};

fn main() {
    println!("=== Confium Mode 1: P-256 Threshold Signing Demo ===\n");

    // Step 1: Generate keypair
    println!("Step 1: Generating P-256 keypair...");
    let keypair = keys::generate_keypair();
    let pk_bytes = keys::public_key_sec1(&keypair.public_key);
    println!(
        "  Public key (SEC1, 65 bytes uncompressed): {}",
        hex::encode(&pk_bytes)
    );
    println!();

    // Step 2: Split secret into 5 shares with T=3
    println!("Step 2: Splitting secret into 5 shares with threshold T=3...");
    let shares = shamir::split_secret(&keypair.secret_scalar, 3, 5);
    for s in &shares {
        let bytes = confium_tc_frost_p256::scalar::scalar_to_bytes(&s.y);
        println!("  Share {}: {}", s.x, hex::encode(bytes));
    }
    println!();

    // Step 3: Recover from any 3 shares
    println!("Step 3: Recovering secret from shares 1, 3, 5...");
    let subset: Vec<&shamir::Share> = vec![&shares[0], &shares[2], &shares[4]];
    let recovered = shamir::recover_secret(&subset).expect("recover");
    let original_bytes = confium_tc_frost_p256::scalar::scalar_to_bytes(&keypair.secret_scalar);
    let recovered_bytes = confium_tc_frost_p256::scalar::scalar_to_bytes(&recovered);
    assert_eq!(
        original_bytes, recovered_bytes,
        "recovered secret must match original"
    );
    println!("  Secret recovered successfully (matches original).");
    println!();

    // Step 4: Sign a message
    let message = b"Confium P-256 threshold signature demo";
    println!(
        "Step 4: Signing message: {:?}",
        std::str::from_utf8(message).unwrap()
    );
    let signed = sign::sign_message(&keypair, message).expect("sign");
    println!(
        "  DER signature ({} bytes): {}",
        signed.der_bytes.len(),
        hex::encode(&signed.der_bytes)
    );
    println!();

    // Step 5: Verify under the public key
    println!("Step 5: Verifying signature under public key...");
    let verifying = keypair.to_verifying_key();
    let sig = Signature::from_der(&signed.der_bytes).expect("parse sig");
    verifying.verify(message, &sig).expect("verify");
    println!("  Signature VALID.");
    println!();

    println!("=== Demo complete. Real P-256 Shamir + ECDSA verified end-to-end. ===");
}
