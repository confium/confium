//! Threshold BLS signature for cross-organization aggregation.
//!
//! BLS signatures natively aggregate: many signatures over distinct
//! messages under different public keys can be combined into a single
//! short signature. Useful for OIML MAA (Mutual Acceptance Arrangement):
//! multiple IAs co-sign a single CNML certificate, aggregated into one.
//!
//! See `TODO.roadmap/04-threshold-cryptography.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

use serde::{Deserialize, Serialize};

/// Algorithm identifier (uses BLS12-381 curve).
pub const ALGORITHM: &str = "BLS-threshold";

/// BLS public key (48 bytes on BLS12-381 G2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Public key bytes.
    pub bytes: Vec<u8>,
}

/// BLS signature (96 bytes on BLS12-381 G1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Signature bytes.
    pub bytes: Vec<u8>,
}

/// Threshold share of BLS signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Party index.
    pub party_index: u32,
    /// Share bytes (32 bytes).
    pub bytes: Vec<u8>,
}

/// Errors during BLS operations.
#[derive(Debug, thiserror::Error)]
pub enum BlsError {
    /// Threshold not met.
    #[error("threshold not met")]
    ThresholdNotMet,
    /// Aggregation failed.
    #[error("aggregation failed: {0}")]
    AggregationFailed(String),
    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,
}

/// Aggregate multiple BLS signatures over the same message into one.
///
/// Mock: XORs all signature bytes together.
pub fn aggregate_signatures(signatures: &[Signature]) -> Result<Signature, BlsError> {
    if signatures.is_empty() {
        return Err(BlsError::AggregationFailed(
            "no signatures to aggregate".into(),
        ));
    }
    let mut combined = signatures[0].bytes.clone();
    for sig in &signatures[1..] {
        for (i, b) in sig.bytes.iter().enumerate() {
            if i < combined.len() {
                combined[i] ^= b;
            }
        }
    }
    Ok(Signature { bytes: combined })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_two_signatures() {
        let s1 = Signature {
            bytes: vec![0xFF; 96],
        };
        let s2 = Signature {
            bytes: vec![0xFF; 96],
        };
        let combined = aggregate_signatures(&[s1, s2]).unwrap();
        // XOR of two identical = all zeros
        assert!(combined.bytes.iter().all(|b| *b == 0));
    }

    #[test]
    fn empty_aggregation_fails() {
        let result = aggregate_signatures(&[]);
        assert!(result.is_err());
    }
}
