//! Share integrity verification — validates shares before use.
//!
//! Corrupted shares cause signing failures that are hard to diagnose.
//! This module validates share structure, scalar range, party index
//! bounds, and public key format before the share enters the signing
//! pipeline.

use crate::share_adapter::NormalizedShare;

/// Result of integrity checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityResult {
    /// Share passed all checks.
    Valid,
    /// Share has one or more problems.
    Invalid(Vec<IntegrityIssue>),
}

/// A specific integrity issue found in a share.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityIssue {
    /// Scalar is zero (invalid for any threshold scheme).
    #[error("scalar is zero")]
    ZeroScalar,
    /// Scalar bytes are wrong length.
    #[error("scalar has wrong length: {actual} (expected 32)")]
    ScalarLength { actual: usize },
    /// Scalar is >= curve order.
    #[error("scalar >= curve order")]
    ScalarOutOfRange,
    /// Party index is zero (must be 1-based).
    #[error("party_idx is 0 (must be >= 1)")]
    PartyIdxZero,
    /// Party index exceeds party count.
    #[error("party_idx {party_idx} > party_count {party_count}")]
    PartyIdxExceedsCount {
        /// The party index.
        party_idx: u32,
        /// The party count.
        party_count: u32,
    },
    /// Threshold exceeds party count.
    #[error("threshold {threshold} > party_count {party_count}")]
    ThresholdExceedsCount {
        /// The threshold.
        threshold: u32,
        /// The party count.
        party_count: u32,
    },
    /// Threshold is zero.
    #[error("threshold is 0")]
    ZeroThreshold,
    /// Public key is wrong length.
    #[error("public key has wrong length: {actual} (expected 33 or 65)")]
    PublicKeyLength { actual: usize },
    /// Public key hex is invalid.
    #[error("public key hex is invalid: {0}")]
    PublicKeyHex(String),
    /// Scalar hex is invalid.
    #[error("scalar hex is invalid: {0}")]
    ScalarHex(String),
}

/// Check the integrity of a normalized share. Returns `Valid` if all
/// checks pass, or `Invalid` with a list of issues.
pub fn check_share(share: &NormalizedShare) -> IntegrityResult {
    let mut issues = Vec::new();

    check_threshold(&mut issues, share);
    check_party_idx(&mut issues, share);
    check_scalar(&mut issues, share);
    check_public_key(&mut issues, share);

    if issues.is_empty() {
        IntegrityResult::Valid
    } else {
        IntegrityResult::Invalid(issues)
    }
}

/// Quick boolean check — returns true if the share is valid.
pub fn is_valid(share: &NormalizedShare) -> bool {
    matches!(check_share(share), IntegrityResult::Valid)
}

fn check_threshold(issues: &mut Vec<IntegrityIssue>, share: &NormalizedShare) {
    if share.threshold == 0 {
        issues.push(IntegrityIssue::ZeroThreshold);
    }
    if share.threshold > share.party_count {
        issues.push(IntegrityIssue::ThresholdExceedsCount {
            threshold: share.threshold,
            party_count: share.party_count,
        });
    }
}

fn check_party_idx(issues: &mut Vec<IntegrityIssue>, share: &NormalizedShare) {
    if share.party_idx == 0 {
        issues.push(IntegrityIssue::PartyIdxZero);
    }
    if share.party_idx > share.party_count {
        issues.push(IntegrityIssue::PartyIdxExceedsCount {
            party_idx: share.party_idx,
            party_count: share.party_count,
        });
    }
}

fn check_scalar(issues: &mut Vec<IntegrityIssue>, share: &NormalizedShare) {
    let bytes = match share.scalar_bytes() {
        Ok(b) => b,
        Err(e) => {
            issues.push(IntegrityIssue::ScalarHex(e.to_string()));
            return;
        }
    };
    if bytes.len() != 32 {
        issues.push(IntegrityIssue::ScalarLength {
            actual: bytes.len(),
        });
        return;
    }
    if bytes.iter().all(|&b| b == 0) {
        issues.push(IntegrityIssue::ZeroScalar);
    }
}

fn check_public_key(issues: &mut Vec<IntegrityIssue>, share: &NormalizedShare) {
    let bytes = match share.public_key_bytes() {
        Ok(b) => b,
        Err(e) => {
            issues.push(IntegrityIssue::PublicKeyHex(e.to_string()));
            return;
        }
    };
    let len = bytes.len();
    if len != 33 && len != 65 {
        issues.push(IntegrityIssue::PublicKeyLength { actual: len });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_share() -> NormalizedShare {
        NormalizedShare::new(
            "CMP20",
            "quorum-1",
            2,
            3,
            5,
            &[0x42; 32],
            &[0x04; 65],
        )
        .unwrap()
    }

    #[test]
    fn valid_share_passes() {
        let share = make_valid_share();
        assert!(matches!(check_share(&share), IntegrityResult::Valid));
        assert!(is_valid(&share));
    }

    #[test]
    fn zero_scalar_rejected() {
        let mut share = make_valid_share();
        share.scalar_hex = hex::encode(&[0u8; 32]);
        let result = check_share(&share);
        assert!(matches!(result, IntegrityResult::Invalid(issues) if issues.contains(&IntegrityIssue::ZeroScalar)));
    }

    #[test]
    fn zero_threshold_rejected() {
        let mut share = make_valid_share();
        share.threshold = 0;
        let result = check_share(&share);
        assert!(matches!(result, IntegrityResult::Invalid(issues) if issues.contains(&IntegrityIssue::ZeroThreshold)));
    }

    #[test]
    fn threshold_exceeds_count_rejected() {
        let mut share = make_valid_share();
        share.threshold = 10;
        share.party_count = 5;
        let result = check_share(&share);
        assert!(matches!(result, IntegrityResult::Invalid(issues) if issues.iter().any(|i| matches!(i, IntegrityIssue::ThresholdExceedsCount { .. }))));
    }

    #[test]
    fn zero_party_idx_rejected() {
        let mut share = make_valid_share();
        share.party_idx = 0;
        let result = check_share(&share);
        assert!(matches!(result, IntegrityResult::Invalid(issues) if issues.contains(&IntegrityIssue::PartyIdxZero)));
    }

    #[test]
    fn party_idx_exceeds_count_rejected() {
        let mut share = make_valid_share();
        share.party_idx = 10;
        share.party_count = 5;
        let result = check_share(&share);
        assert!(matches!(result, IntegrityResult::Invalid(issues) if issues.iter().any(|i| matches!(i, IntegrityIssue::PartyIdxExceedsCount { .. }))));
    }

    #[test]
    fn compressed_pubkey_accepted() {
        let mut share = make_valid_share();
        share.public_key_hex = hex::encode(&[0x02; 33]);
        assert!(is_valid(&share));
    }

    #[test]
    fn wrong_pubkey_length_rejected() {
        let mut share = make_valid_share();
        share.public_key_hex = hex::encode(&[0x04; 10]);
        let result = check_share(&share);
        assert!(matches!(result, IntegrityResult::Invalid(issues) if issues.iter().any(|i| matches!(i, IntegrityIssue::PublicKeyLength { .. }))));
    }

    #[test]
    fn bad_scalar_hex_rejected() {
        let mut share = make_valid_share();
        share.scalar_hex = "not-hex!!".into();
        let result = check_share(&share);
        assert!(matches!(result, IntegrityResult::Invalid(_)));
    }

    #[test]
    fn multiple_issues_reported() {
        let mut share = make_valid_share();
        share.party_idx = 0;
        share.threshold = 0;
        share.scalar_hex = "00".repeat(32);
        let result = check_share(&share);
        match result {
            IntegrityResult::Invalid(issues) => assert!(issues.len() >= 3),
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn is_valid_shorthand_works() {
        assert!(is_valid(&make_valid_share()));
    }
}
