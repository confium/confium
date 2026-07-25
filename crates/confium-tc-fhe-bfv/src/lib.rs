//! Threshold BFV fully homomorphic encryption — research prototype (P3).
//!
//! Computation on encrypted data without decryption, plus threshold:
//! computation requires quorum agreement. Long horizon research.
//!
//! For OIML: statistical analysis of test reports without decrypting
//! individual reports. Compute aggregate quality metrics across
//! manufacturers without revealing individual measurements.
//!
//! See `TODO.roadmap/40-threshold-fhe.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// BFV parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BfvParams {
    /// Polynomial degree (typically 4096-32768).
    pub polynomial_degree: usize,
    /// Plaintext modulus.
    pub plaintext_modulus: u64,
    /// Coefficient modulus chain (one per level).
    pub coefficient_modulus: Vec<u64>,
    /// Security level in bits (128 = current standard).
    pub security_level: u32,
}

impl BfvParams {
    /// Recommended parameters for 128-bit security with moderate performance.
    pub fn recommended_128() -> Self {
        Self {
            polynomial_degree: 4096,
            plaintext_modulus: 65537,
            coefficient_modulus: vec![0xFFFFFFFFFFFFFFF7u64],
            security_level: 128,
        }
    }
}

/// BFV public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BfvPublicKey {
    /// Parameters used to generate the key.
    pub params: BfvParams,
    /// Public key bytes (serialized polynomial pair).
    pub bytes: Vec<u8>,
}

/// Secret key share (held by one party).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BfvSecretKeyShare {
    /// Party index.
    pub party_index: u32,
    /// Share bytes (one polynomial per share).
    pub bytes: Vec<u8>,
}

/// BFV ciphertext (pair of polynomials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BfvCiphertext {
    /// C1 component.
    pub c1: Vec<u8>,
    /// C2 component.
    pub c2: Vec<u8>,
}

/// Errors during BFV operations.
#[derive(Debug, thiserror::Error)]
pub enum BfvError {
    /// Parameters incompatible.
    #[error("parameters incompatible: {0}")]
    IncompatibleParams(String),
    /// Threshold not met for decryption.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Have count.
        have: usize,
        /// Need count.
        need: u32,
    },
    /// Operation requires academic collaborator.
    #[error("threshold BFV is research-only (P3): {0}")]
    ResearchOnly(String),
}

/// Validate that BFV parameters are reasonable.
pub fn validate_params(params: &BfvParams) -> Result<(), BfvError> {
    if params.polynomial_degree < 1024 {
        return Err(BfvError::IncompatibleParams(format!(
            "polynomial_degree too small: {}",
            params.polynomial_degree
        )));
    }
    if !params.polynomial_degree.is_power_of_two() {
        return Err(BfvError::IncompatibleParams(format!(
            "polynomial_degree must be power of two: {}",
            params.polynomial_degree
        )));
    }
    if params.security_level < 128 {
        return Err(BfvError::IncompatibleParams(format!(
            "security_level below 128: {}",
            params.security_level
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_params_validate() {
        let params = BfvParams::recommended_128();
        validate_params(&params).unwrap();
    }

    #[test]
    fn non_power_of_two_rejected() {
        let params = BfvParams {
            polynomial_degree: 5000, // not power of two
            ..BfvParams::recommended_128()
        };
        let result = validate_params(&params);
        assert!(matches!(result, Err(BfvError::IncompatibleParams(_))));
    }

    #[test]
    fn low_security_rejected() {
        let params = BfvParams {
            security_level: 64,
            ..BfvParams::recommended_128()
        };
        let result = validate_params(&params);
        assert!(matches!(result, Err(BfvError::IncompatibleParams(_))));
    }
}
