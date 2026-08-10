//! Threshold BLS signature for cross-organization aggregation.
//!
//! **⚠️ RESEARCH PROTOTYPE — NOT FOR PRODUCTION USE.**
//!
//! This crate exists to validate the threshold-BLS API shape and
//! coordinator integration. The actual aggregation is a **mock**:
//! signature bytes are XOR-folded rather than combined via the
//! BLS12-381 pairing. The mock:
//!
//! - Is NOT cryptographically secure — XOR-folding signatures is a
//!   well-known anti-pattern (sponge attacks recover individual
//!   signatures from aggregates).
//! - Does NOT use the `blst` or `ark-bls12-381` crates.
//! - Does NOT produce signatures that verify under standard BLS
//!   libraries (randombytes, blst, py_ecc, etc.).
//!
//! A production BLS implementation is tracked as a separate work
//! stream (see `TODO.roadmap/04-threshold-cryptography.md`).
//! Until that lands, treat every output from this crate as
//! unverified placeholder data.
//!
//! ## What this crate IS good for
//!
//! - Validating the coordinator's session-driver wiring for an
//!   aggregation-style scheme.
//! - Testing the FFI surface and language bindings without needing
//!   real BLS12-381 native dependencies.
//! - Reference for what the eventual API shape will look like.
//!
//! ## What this crate is NOT good for
//!
//! - Real signature verification.
//! - Cross-organization MAA (Mutual Acceptance Arrangement) signing.
//! - Any deployment where the signature protects a real asset.
//!
//! BLS signatures natively aggregate: many signatures over distinct
//! messages under different public keys can be combined into a single
//! short signature. Useful for OIML MAA: multiple IAs co-sign a
//! single CNML certificate, aggregated into one.
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
    /// Fewer than T partial signatures were supplied to an aggregation
    /// call. The threshold was set during DKG; the caller must collect
    /// at least T partials before aggregating.
    /// Caller action: wait for more partials from peers.
    #[error("threshold not met")]
    ThresholdNotMet,
    /// Aggregation failed — typically because the supplied partials
    /// are inconsistent (different messages, wrong group operation).
    /// The string describes the specific failure.
    /// Caller action: inspect the message; restart the round if needed.
    #[error("aggregation failed: {0}")]
    AggregationFailed(String),
    /// The aggregated signature failed verification against the joint
    /// public key. Indicates either a Byzantine participant or a
    /// corrupted public key / message.
    /// Caller action: re-run the verification with a known-good key
    /// before reporting the issue.
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
