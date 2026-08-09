//! P-256 ECDSA signing.
//!
//! Wraps `p256::ecdsa` for standard signature production and verification.
//! Combined with `crate::shamir`, this provides a complete (if simplified)
//! threshold ECDSA workflow for testing and integration.

use crate::keys::Keypair;
use p256::ecdsa::{Signature, signature::Signer};
use thiserror::Error;

/// Result of signing: DER-encoded signature bytes plus the raw signature object.
#[derive(Debug, Clone)]
pub struct Signed {
    /// DER-encoded signature (ANS.1 SEQUENCE of two INTEGERs).
    pub der_bytes: Vec<u8>,
    /// Raw fixed-size signature (r || s, 64 bytes).
    pub fixed_bytes: Vec<u8>,
}

/// Errors during signing.
#[derive(Debug, Error)]
pub enum SignError {
    /// Signing failed (e.g., RNG failure).
    #[error("signing failed: {0}")]
    Sign(String),
}

/// Sign `message` with the keypair. Uses SHA-256 as the digest.
pub fn sign_message(keypair: &Keypair, message: &[u8]) -> Result<Signed, SignError> {
    let signing_key = keypair.to_signing_key();
    let sig: Signature = signing_key
        .try_sign(message)
        .map_err(|e| SignError::Sign(format!("p256 sign: {e:?}")))?;
    Ok(Signed {
        der_bytes: sig.to_der().to_bytes().to_vec(),
        fixed_bytes: sig.to_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn sign_and_verify_round_trip() {
        let keypair = generate_keypair();
        let msg = b"hello, threshold world";
        let signed = sign_message(&keypair, msg).unwrap();

        let verifying = keypair.to_verifying_key();
        let sig = Signature::from_der(&signed.der_bytes).unwrap();
        verifying.verify(msg, &sig).unwrap();
    }

    #[test]
    fn signature_bytes_are_distinct() {
        let keypair = generate_keypair();
        let s1 = sign_message(&keypair, b"message one").unwrap();
        let s2 = sign_message(&keypair, b"message two").unwrap();
        assert_ne!(s1.der_bytes, s2.der_bytes);
    }

    #[test]
    fn fixed_size_signature_is_64_bytes() {
        let keypair = generate_keypair();
        let signed = sign_message(&keypair, b"x").unwrap();
        assert_eq!(signed.fixed_bytes.len(), 64);
    }
}
