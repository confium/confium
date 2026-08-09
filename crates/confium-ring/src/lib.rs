//! Threshold ring signatures — research prototype (P3).
//!
//! For sensitive national-security type approvals: hide WHICH
//! directors signed. Public can verify the signature; watchdogs
//! know SOMETHING was signed; signer identities anonymized among
//! the eligible set; revealed only to designated auditor.
//!
//! Currently no production-quality threshold ring signature
//! implementation exists. This is research frontier — long horizon
//! beyond Q2 2027 NIST MPTS submission.
//!
//! See `TODO.roadmap/39-threshold-ring-signatures.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

use serde::{Deserialize, Serialize};

/// A ring signature — anonymous signature on behalf of a ring of eligible signers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingSignature {
    /// All eligible signers' public keys (the "ring").
    pub ring_members: Vec<Vec<u8>>,
    /// The signature itself.
    pub signature: Vec<u8>,
    /// How many ring members collaborated to produce this signature (T).
    pub signer_count: u32,
    /// Optional auditor-encrypted identity evidence.
    pub auditor_evidence: Option<Vec<u8>>,
}

/// Errors during ring signature operations.
#[derive(Debug, thiserror::Error)]
pub enum RingError {
    /// Ring too small.
    #[error("ring too small: {0} members")]
    RingTooSmall(usize),
    /// Signer count exceeds ring size.
    #[error("signer_count {signer_count} exceeds ring size {ring_size}")]
    SignerCountExceeds {
        /// Number of signers.
        signer_count: u32,
        /// Ring size.
        ring_size: usize,
    },
    /// Research-only operation.
    #[error("threshold ring signatures are research-only (P3): {0}")]
    ResearchOnly(String),
}

/// Verify the structural validity of a ring signature (not the crypto).
pub fn validate_structure(sig: &RingSignature) -> Result<(), RingError> {
    if sig.ring_members.len() < 2 {
        return Err(RingError::RingTooSmall(sig.ring_members.len()));
    }
    if sig.signer_count as usize > sig.ring_members.len() {
        return Err(RingError::SignerCountExceeds {
            signer_count: sig.signer_count,
            ring_size: sig.ring_members.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_structure_passes() {
        let sig = RingSignature {
            ring_members: vec![vec![0u8; 32], vec![1u8; 32], vec![2u8; 32]],
            signature: vec![0u8; 64],
            signer_count: 2,
            auditor_evidence: None,
        };
        validate_structure(&sig).unwrap();
    }

    #[test]
    fn ring_too_small_fails() {
        let sig = RingSignature {
            ring_members: vec![vec![0u8; 32]],
            signature: vec![0u8; 64],
            signer_count: 1,
            auditor_evidence: None,
        };
        let result = validate_structure(&sig);
        assert!(matches!(result, Err(RingError::RingTooSmall(_))));
    }

    #[test]
    fn signer_count_exceeds_fails() {
        let sig = RingSignature {
            ring_members: vec![vec![0u8; 32], vec![1u8; 32]],
            signature: vec![0u8; 64],
            signer_count: 3,
            auditor_evidence: None,
        };
        let result = validate_structure(&sig);
        assert!(matches!(result, Err(RingError::SignerCountExceeds { .. })));
    }
}
