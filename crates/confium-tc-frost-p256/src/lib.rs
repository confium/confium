//! FROST threshold signature over ECDSA P-256.
//!
//! Implements real Shamir secret sharing over the P-256 scalar field
//! plus real P-256 ECDSA signing/verification. Used by OIML CNML IA
//! quorum and Mode 2 enterprise PKI replacement for compatibility
//! with existing P-256 PKI.
//!
//! ## Important: threshold ECDSA caveats
//!
//! True threshold ECDSA signing (where the secret is never reconstructed)
//! requires the Multiplicative-to-Additive (MtA) protocol used by
//! `confium-tc-cmp20` and `confium-tc-gg18`. This crate provides:
//!
//! - **Real Shamir secret sharing** over P-256 scalars
//! - **Real Lagrange interpolation** to reconstruct the secret from T shares
//! - **Real P-256 ECDSA** sign/verify
//!
//! For demonstration, integration testing, and as the underlying primitives
//! for FROST-style schemes. For production threshold ECDSA signing,
//! use `confium-tc-cmp20`.
//!
//! See `TODO.roadmap/04-threshold-cryptography.md` for the FFI spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod keys;
pub mod scalar;
pub mod shamir;
pub mod sign;

pub use keys::*;
pub use shamir::*;
pub use sign::*;

/// Algorithm identifier for FROST-P256.
pub const ALGORITHM: &str = "FROST-P256";

/// Re-export for convenience.
pub use p256;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn full_threshold_signing_lifecycle() {
        // 1. Trusted dealer generates a keypair and splits into 5 shares, T=3.
        let keypair = keys::generate_keypair();
        let shares = shamir::split_secret(&keypair.secret_scalar, 3, 5);

        // 2. Any 3 shares can reconstruct the secret.
        let subset: Vec<&shamir::Share> = shares.iter().take(3).collect();
        let reconstructed = shamir::recover_secret(&subset).expect("recover");
        assert_eq!(reconstructed, keypair.secret_scalar);

        // 3. Sign with the keypair.
        let message = b"hello, threshold world";
        let signature = sign::sign_message(&keypair, message).expect("sign");

        // 4. Verify under the public key using standard p256::ecdsa.
        use p256::ecdsa::{Signature, signature::Verifier};
        let verifying = keypair.to_verifying_key();
        let sig = Signature::from_der(&signature.der_bytes).expect("parse sig");
        verifying.verify(message, &sig).expect("verify");
    }

    #[test]
    fn insufficient_shares_fail() {
        let keypair = keys::generate_keypair();
        let shares = shamir::split_secret(&keypair.secret_scalar, 3, 5);
        let subset: Vec<&shamir::Share> = shares.iter().take(2).collect();
        let result = shamir::recover_secret(&subset);
        // With 2 shares when 3 needed, recovery should fail (return wrong value or error).
        // Real Shamir: recovery is undefined for insufficient shares.
        // We accept either an error or a wrong (non-matching) result.
        match result {
            Ok(r) => assert_ne!(r, keypair.secret_scalar, "should not match with <T shares"),
            Err(_) => {}
        }
    }

    #[test]
    fn different_share_subsets_recover_same_secret() {
        let keypair = keys::generate_keypair();
        let shares = shamir::split_secret(&keypair.secret_scalar, 3, 5);

        let subset_a: Vec<&shamir::Share> = vec![&shares[0], &shares[1], &shares[2]];
        let subset_b: Vec<&shamir::Share> = vec![&shares[1], &shares[3], &shares[4]];

        let recovered_a = shamir::recover_secret(&subset_a).expect("recover A");
        let recovered_b = shamir::recover_secret(&subset_b).expect("recover B");

        assert_eq!(recovered_a, recovered_b);
        assert_eq!(recovered_a, keypair.secret_scalar);
    }
}
