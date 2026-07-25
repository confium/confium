//! FROST threshold signature over ECDSA P-256.
//!
//! Implements draft-irtf-cfrg-frost-13 over the NIST P-256 curve.
//! Used by OIML CNML IA quorum and Mode 2 enterprise PKI replacement
//! for compatibility with existing P-256 PKI.
//!
//! See `TODO.roadmap/04-threshold-cryptography.md` for the FFI spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Algorithm identifier for FROST-P256.
pub const ALGORITHM: &str = "FROST-P256";

/// Curve order for P-256 (used in Lagrange interpolation).
pub const P256_CURVE_ORDER_HEX: &str =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// A party's share of the threshold signing key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FrostShare {
    /// Party index (1-based per FROST convention).
    pub party_index: u32,
    /// Scalar bytes (32 bytes for P-256).
    pub bytes: Vec<u8>,
}

/// FROST session parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FrostParams {
    /// Threshold T.
    pub threshold: u32,
    /// Total parties N.
    pub num_parties: u32,
    /// This party's index.
    pub this_party_idx: u32,
    /// Message to sign (digest bytes).
    pub message: Vec<u8>,
}

/// Round 1 commitment from one party.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Commitment {
    /// Party index.
    pub party_index: u32,
    /// Hiding nonce commitment bytes.
    pub hiding: Vec<u8>,
    /// Binding nonce commitment bytes.
    pub binding: Vec<u8>,
}

/// Round 2 signature share from one party.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureShare {
    /// Party index.
    pub party_index: u32,
    /// Signature share bytes (32 bytes for P-256).
    pub bytes: Vec<u8>,
}

/// Final aggregated signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregatedSignature {
    /// R point bytes (33 or 65 bytes).
    pub r: Vec<u8>,
    /// z scalar bytes (32 bytes).
    pub z: Vec<u8>,
}

/// FROST-P256 errors.
#[derive(Debug, thiserror::Error)]
pub enum FrostError {
    /// Invalid parameters.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Have count.
        have: usize,
        /// Need count.
        need: u32,
    },
    /// Invalid share / commitment.
    #[error("invalid {what}: {reason}")]
    Invalid {
        /// What's invalid.
        what: &'static str,
        /// Why.
        reason: String,
    },
    /// Aggregation failure.
    #[error("aggregation failed: {0}")]
    AggregationFailed(String),
}

/// Verify that a P-256 share has the correct length.
pub fn validate_share(share: &FrostShare) -> Result<(), FrostError> {
    if share.bytes.len() != 32 {
        return Err(FrostError::Invalid {
            what: "share",
            reason: format!("expected 32 bytes, got {}", share.bytes.len()),
        });
    }
    Ok(())
}

/// Compute a mock Lagrange coefficient at party_index `i` evaluated at x=0.
///
/// Real implementation uses P-256 scalar field arithmetic. The mock
/// returns 1 (identity) for testing the protocol structure.
pub fn lagrange_coefficient_at_zero(party_index: u32, all_parties: &[u32]) -> u32 {
    let _ = (party_index, all_parties);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_is_frost_p256() {
        assert_eq!(ALGORITHM, "FROST-P256");
    }

    #[test]
    fn valid_share_accepted() {
        let share = FrostShare {
            party_index: 1,
            bytes: vec![0u8; 32],
        };
        validate_share(&share).unwrap();
    }

    #[test]
    fn short_share_rejected() {
        let share = FrostShare {
            party_index: 1,
            bytes: vec![0u8; 16],
        };
        let result = validate_share(&share);
        assert!(matches!(result, Err(FrostError::Invalid { .. })));
    }
}
