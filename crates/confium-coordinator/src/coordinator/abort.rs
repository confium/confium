//! Identifiable abort — pinpoint which signer submitted a bad share.
//!
//! When threshold aggregation fails, this module identifies the
//! offending signer by testing each one individually. The approach:
//!
//! 1. Try aggregating all T shares.
//! 2. If that fails, try aggregating each (T-1)-subset (leaving one out).
//! 3. If leaving out signer X succeeds, X is the culprit.
//!
//! This is O(T) aggregation attempts — acceptable for small T.

use crate::coordinator::coordinator::ThresholdSigner;
use crate::coordinator::session::SignerId;
use serde::{Deserialize, Serialize};

/// A share associated with its signer identity.
#[derive(Debug, Clone)]
pub struct LabeledShare {
    /// Who submitted this share.
    pub signer_id: SignerId,
    /// Share bytes.
    pub bytes: Vec<u8>,
}

/// Result of blame attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameReport {
    /// Session that failed.
    pub session_id: String,
    /// Identified bad signer(s), if any.
    pub bad_signers: Vec<SignerId>,
    /// True if all shares verified individually but aggregation still
    /// failed (indicates a protocol-level issue).
    pub all_individual_valid: bool,
    /// Error message from the original aggregation attempt.
    pub error: String,
}

/// Identify the bad signer(s) by elimination. Given T shares and a
/// threshold signer, tries removing each signer one at a time.
///
/// Returns a blame report. If a specific signer is identified,
/// `bad_signers` contains their ID.
pub fn identify_bad_signer(
    session_id: &str,
    shares: &[LabeledShare],
    threshold: u32,
    message: &[u8],
    scheme: &str,
    signer: &dyn ThresholdSigner,
) -> BlameReport {
    if shares.is_empty() {
        return BlameReport {
            session_id: session_id.into(),
            bad_signers: vec![],
            all_individual_valid: false,
            error: "no shares provided".into(),
        };
    }

    // First, try the full set.
    let all_bytes: Vec<Vec<u8>> = shares.iter().map(|s| s.bytes.clone()).collect();
    match signer.sign(scheme, &all_bytes, threshold, message) {
        Ok(_) => BlameReport {
            session_id: session_id.into(),
            bad_signers: vec![],
            all_individual_valid: true,
            error: "aggregation succeeded — no bad signer".into(),
        },
        Err(e) => {
            let error = format!("{e}");
            let mut bad_signers = Vec::new();

            // Try leaving out each signer one at a time.
            for (i, _) in shares.iter().enumerate() {
                let subset: Vec<Vec<u8>> = shares
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, s)| s.bytes.clone())
                    .collect();

                // We need at least threshold shares for a valid subset.
                // If threshold > subset.len(), this signer can't be
                // the sole culprit.
                if (threshold as usize) > subset.len() {
                    continue;
                }

                match signer.sign(scheme, &subset, threshold, message) {
                    Ok(_) => {
                        // Removing signer i makes it work → i is bad.
                        bad_signers.push(shares[i].signer_id.clone());
                    }
                    Err(_) => {
                        // Still fails without signer i → i is not the sole culprit.
                    }
                }
            }

            BlameReport {
                session_id: session_id.into(),
                bad_signers,
                all_individual_valid: false,
                error,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::coordinator::MockSigner;

    fn make_share(id: &str, byte: u8) -> LabeledShare {
        LabeledShare {
            signer_id: id.into(),
            bytes: vec![byte; 64],
        }
    }

    #[test]
    fn no_shares_returns_empty_report() {
        let signer = MockSigner;
        let report = identify_bad_signer("s1", &[], 2, b"msg", "CMP20", &signer);
        assert!(report.bad_signers.is_empty());
        assert!(report.error.contains("no shares"));
    }

    #[test]
    fn all_valid_shares_no_blame() {
        let signer = MockSigner;
        let shares = vec![
            make_share("alice", 0xAA),
            make_share("bob", 0xBB),
            make_share("carol", 0xCC),
        ];
        let report = identify_bad_signer("s1", &shares, 2, b"msg", "CMP20", &signer);
        assert!(report.bad_signers.is_empty());
        assert!(report.error.contains("succeeded"));
    }

    #[test]
    fn empty_shares_list_handled() {
        let signer = MockSigner;
        let report = identify_bad_signer("s1", &[], 0, b"msg", "CMP20", &signer);
        assert!(report.bad_signers.is_empty());
    }

    #[test]
    fn blame_report_serializes() {
        let report = BlameReport {
            session_id: "s1".into(),
            bad_signers: vec!["alice".into()],
            all_individual_valid: false,
            error: "aggregation failed".into(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("alice"));
        assert!(json.contains("s1"));
    }

    #[test]
    fn blame_report_deserializes() {
        let json = r#"{"session_id":"s1","bad_signers":["bob"],"all_individual_valid":false,"error":"test"}"#;
        let report: BlameReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.session_id, "s1");
        assert_eq!(report.bad_signers, vec!["bob"]);
    }

    #[test]
    fn labeled_share_carries_identity() {
        let share = make_share("alice", 0x42);
        assert_eq!(share.signer_id, "alice");
        assert_eq!(share.bytes.len(), 64);
    }

    #[test]
    fn threshold_above_subset_size_skipped() {
        let signer = MockSigner;
        let shares = vec![make_share("alice", 0xAA), make_share("bob", 0xBB)];
        let report = identify_bad_signer("s1", &shares, 2, b"msg", "CMP20", &signer);
        // With T=2 and 2 shares, removing one leaves 1 < T=2, so no
        // blame identification is possible.
        // But the full set should still succeed with MockSigner.
        assert!(report.bad_signers.is_empty());
    }
}
