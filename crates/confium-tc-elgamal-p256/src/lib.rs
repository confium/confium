//! Threshold ElGamal over P-256.
//!
//! Mature, well-analyzed threshold encryption scheme suitable for
//! medium-term sealed data (5-10 year appeals window in OIML CNML).
//!
//! See `TODO.roadmap/31-threshold-encryption.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Algorithm identifier.
pub const ALGORITHM: &str = "ElGamal-P256-threshold";

/// Public key (one EC point, 65 bytes uncompressed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Public key bytes (uncompressed point).
    pub bytes: Vec<u8>,
}

/// Share of the secret key held by one party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// Party index.
    pub party_index: u32,
    /// Share bytes (32-byte scalar).
    pub bytes: Vec<u8>,
}

/// Ciphertext (pair of EC points).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// First component (ephemeral point).
    pub c1: Vec<u8>,
    /// Second component (shared secret point + message).
    pub c2: Vec<u8>,
}

/// Partial decryption from one party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// Party index.
    pub party_index: u32,
    /// Partial decryption bytes (EC point).
    pub bytes: Vec<u8>,
}

/// Errors during threshold ElGamal operations.
#[derive(Debug, thiserror::Error)]
pub enum ElGamalError {
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Have count.
        have: usize,
        /// Need count.
        need: u32,
    },
    /// Invalid ciphertext.
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),
    /// Invalid share.
    #[error("invalid share: {0}")]
    InvalidShare(String),
}

/// Encapsulate: encrypt a shared secret to `recipient_public_key`.
/// Returns `(ciphertext, shared_secret)`.
///
/// Mock implementation: returns deterministic 32-byte outputs.
pub fn encapsulate(_recipient_public_key: &PublicKey) -> Result<(Ciphertext, Vec<u8>), ElGamalError> {
    Ok((
        Ciphertext {
            c1: vec![1u8; 65],
            c2: vec![2u8; 65],
        },
        vec![0u8; 32],
    ))
}

/// Aggregate partial decryptions into the shared secret.
///
/// Mock: XOR all partials together.
pub fn aggregate_partials(
    partials: &[PartialDecryption],
    threshold: u32,
) -> Result<Vec<u8>, ElGamalError> {
    if (partials.len() as u32) < threshold {
        return Err(ElGamalError::ThresholdNotMet {
            have: partials.len(),
            need: threshold,
        });
    }
    let mut combined = vec![0u8; 32];
    for p in partials {
        for (i, b) in p.bytes.iter().take(32).enumerate() {
            combined[i] ^= b;
        }
    }
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_returns_ciphertext() {
        let pk = PublicKey {
            bytes: vec![0u8; 65],
        };
        let (ct, ss) = encapsulate(&pk).unwrap();
        assert!(!ct.c1.is_empty());
        assert!(!ct.c2.is_empty());
        assert_eq!(ss.len(), 32);
    }

    #[test]
    fn aggregate_below_threshold_fails() {
        let partials = vec![PartialDecryption {
            party_index: 1,
            bytes: vec![0u8; 32],
        }];
        let result = aggregate_partials(&partials, 2);
        assert!(matches!(result, Err(ElGamalError::ThresholdNotMet { .. })));
    }
}
