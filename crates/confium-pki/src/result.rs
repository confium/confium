//! Unified verification result shared across Confium PKI crates.

use serde::{Deserialize, Serialize};

/// Result of a verification operation (cert path, signature, CMS, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Overall validity — true iff every check passed.
    pub valid: bool,
    /// Per-check detail.
    pub checks: Vec<PathFailure>,
}

/// Individual check failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PathFailure {
    /// Certificate is expired.
    Expired,
    /// Certificate is not yet valid.
    NotYetValid,
    /// Signature verification failed.
    SignatureInvalid,
    /// Scope constraint violated.
    ScopeViolation {
        /// Expected scope value.
        expected: String,
        /// Actual scope value.
        actual: String,
    },
    /// Chain exceeds max length.
    ChainTooLong,
    /// Root is not in trust store.
    UntrustedRoot,
    /// Certificate is revoked.
    Revoked {
        /// CRL distribution URL.
        crl_url: String,
        /// Revoked serial number.
        serial: String,
    },
}

impl VerificationResult {
    /// Aggregate multiple verification results into one.
    pub fn aggregate(results: &[VerificationResult]) -> Self {
        let mut combined = VerificationResult {
            valid: true,
            checks: Vec::new(),
        };
        for r in results {
            if !r.valid {
                combined.valid = false;
            }
            combined.checks.extend(r.checks.iter().cloned());
        }
        combined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_passing_results() {
        let r1 = VerificationResult {
            valid: true,
            checks: vec![],
        };
        let r2 = VerificationResult {
            valid: true,
            checks: vec![],
        };
        let combined = VerificationResult::aggregate(&[r1, r2]);
        assert!(combined.valid);
        assert!(combined.checks.is_empty());
    }

    #[test]
    fn aggregate_with_failure_propagates() {
        let r1 = VerificationResult {
            valid: true,
            checks: vec![],
        };
        let r2 = VerificationResult {
            valid: false,
            checks: vec![PathFailure::Expired],
        };
        let combined = VerificationResult::aggregate(&[r1, r2]);
        assert!(!combined.valid);
        assert_eq!(combined.checks.len(), 1);
    }
}
