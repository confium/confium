//! Threshold FROST over ML-DSA-65 — research prototype.
//!
//! Lattice-based threshold signature. Based on FIPS 204 (ML-DSA-65).
//! Threshold variants require MPC over the lattice signing operations;
//! academic work ongoing (Boneh et al. 2024).
//!
//! See `TODO.roadmap/35-pq-composite-signatures.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Algorithm identifier.
pub const ALGORITHM: &str = "FROST-ML-DSA-65";

/// ML-DSA-65 public key size (FIPS 204).
pub const PUBLIC_KEY_SIZE: usize = 1952;

/// ML-DSA-65 signature size.
pub const SIGNATURE_SIZE: usize = 3309;

/// Threshold FROST-ML-DSA-65 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdPublicKey {
    /// Public key bytes.
    pub bytes: Vec<u8>,
}

/// Share of the threshold signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Party index.
    pub party_index: u32,
    /// Share bytes.
    pub bytes: Vec<u8>,
}

/// Errors during FROST-ML-DSA operations.
#[derive(Debug, thiserror::Error)]
pub enum FrostMlDsaError {
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Have count.
        have: usize,
        /// Need count.
        need: u32,
    },
    /// Research-only operation.
    #[error("operation requires academic collaborator: {0}")]
    ResearchOnly(String),
}

/// Validate that a public key has the correct length for ML-DSA-65.
pub fn validate_public_key(pk: &ThresholdPublicKey) -> Result<(), FrostMlDsaError> {
    if pk.bytes.len() != PUBLIC_KEY_SIZE {
        return Err(FrostMlDsaError::ResearchOnly(format!(
            "expected public key length {PUBLIC_KEY_SIZE}, got {}",
            pk.bytes.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_id() {
        assert_eq!(ALGORITHM, "FROST-ML-DSA-65");
    }

    #[test]
    fn validate_correct_size() {
        let pk = ThresholdPublicKey {
            bytes: vec![0u8; PUBLIC_KEY_SIZE],
        };
        validate_public_key(&pk).unwrap();
    }

    #[test]
    fn validate_wrong_size_fails() {
        let pk = ThresholdPublicKey {
            bytes: vec![0u8; 100],
        };
        let result = validate_public_key(&pk);
        assert!(matches!(result, Err(FrostMlDsaError::ResearchOnly(_))));
    }
}
