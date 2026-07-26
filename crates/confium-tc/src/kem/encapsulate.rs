//! Encapsulation (single-party — anyone can encrypt).
//!
//! Threshold KEM encapsulation is identical to single-party KEM
//! encapsulation: generate an ephemeral keypair, derive the shared
//! secret, encrypt the shared secret to the recipient's public key.
//! The difference is in decapsulation: T-of-N parties must collaborate.

use crate::kem::share::ThresholdShare;
use serde::{Deserialize, Serialize};

/// The recipient's threshold public key (algorithm-agnostic bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdPublicKey {
    /// Algorithm identifier (e.g., "ElGamal-P256-threshold", "ML-KEM-768-threshold").
    pub algorithm: String,
    /// Raw key bytes (format depends on algorithm).
    pub bytes: Vec<u8>,
}

/// An encapsulated key — produced by encapsulate, consumed by threshold decapsulate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncapsulatedKey {
    /// Algorithm identifier.
    pub algorithm: String,
    /// Encapsulated key bytes (the "ciphertext" of the KEM).
    pub bytes: Vec<u8>,
}

/// The shared secret derived during encapsulation. The encryptor uses
/// this as the AEAD key to encrypt the actual plaintext.
#[derive(Debug, Clone, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
pub struct SharedSecret {
    /// Raw shared secret bytes.
    pub bytes: Vec<u8>,
}

/// Errors during encapsulation.
#[derive(Debug, thiserror::Error)]
pub enum EncapsulateError {
    /// Unknown algorithm.
    #[error("unknown algorithm: {0}")]
    UnknownAlgorithm(String),
    /// Invalid public key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    /// Backend failure.
    #[error("backend failure: {0}")]
    Backend(String),
}

/// Trait for algorithm implementations of threshold KEM encapsulation.
pub trait Encapsulator {
    /// Encapsulate a fresh shared secret to `recipient_public_key`.
    /// Returns `(encapsulated_key, shared_secret)` — the encryptor keeps
    /// the shared secret for AEAD encryption, the encapsulated key
    /// travels with the ciphertext.
    fn encapsulate(
        &self,
        recipient_public_key: &ThresholdPublicKey,
    ) -> Result<(EncapsulatedKey, SharedSecret), EncapsulateError>;
}

/// In-memory test encapsulator for "mock" algorithm.
///
/// NOT FOR PRODUCTION USE. Generates a random 32-byte shared secret
/// and stores it in the EncapsulatedKey for the decapsulator to recover.
/// Used for testing the session lifecycle without a real crypto backend.
pub struct MockEncapsulator;

impl Encapsulator for MockEncapsulator {
    fn encapsulate(
        &self,
        _recipient_public_key: &ThresholdPublicKey,
    ) -> Result<(EncapsulatedKey, SharedSecret), EncapsulateError> {
        // Deterministic mock: shared secret is 32 zero bytes.
        // EncapsulatedKey carries the algorithm so decapsulator knows what to do.
        Ok((
            EncapsulatedKey {
                algorithm: "mock-threshold-kem".into(),
                bytes: vec![0u8; 32],
            },
            SharedSecret {
                bytes: vec![0u8; 32],
            },
        ))
    }
}

/// Convenience function: encapsulate using the mock encapsulator.
pub fn encapsulate_mock(
    recipient: &ThresholdPublicKey,
) -> Result<(EncapsulatedKey, SharedSecret), EncapsulateError> {
    MockEncapsulator.encapsulate(recipient)
}

/// Marker for the decapsulator side — verifies the share is for the right algorithm.
pub fn validate_share_for_algorithm(
    share: &ThresholdShare,
    algorithm: &str,
) -> Result<(), EncapsulateError> {
    if share.algorithm != algorithm {
        return Err(EncapsulateError::InvalidPublicKey(format!(
            "share algorithm {} does not match expected {}",
            share.algorithm, algorithm
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_encapsulator_round_trip_data() {
        let pk = ThresholdPublicKey {
            algorithm: "mock-threshold-kem".into(),
            bytes: vec![1u8; 32],
        };
        let (ek, ss) = encapsulate_mock(&pk).unwrap();
        assert_eq!(ek.bytes.len(), 32);
        assert_eq!(ss.bytes.len(), 32);
    }

    #[test]
    fn validate_share_checks_algorithm() {
        let share = ThresholdShare {
            algorithm: "different-alg".into(),
            party_index: 0,
            bytes: vec![],
        };
        let result = validate_share_for_algorithm(&share, "expected-alg");
        assert!(result.is_err());
    }
}
