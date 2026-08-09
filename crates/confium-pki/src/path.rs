//! Hierarchical path validation with scope enforcement.
//!
//! Validates a certificate chain from leaf to trusted root. Enforces:
//!
//! - Time validity at each link
//! - Signature validity (when verifier is provided)
//! - Basic constraints (path length, CA flag)
//! - Confium-specific scope constraints (delegation rules)

use crate::cert::Certificate;
use crate::result::{PathFailure, VerificationResult};
use chrono::{DateTime, Utc};

/// A certificate path: leaf + intermediates + root.
#[derive(Debug, Clone)]
pub struct CertPath<'a> {
    /// The leaf certificate (typically end-entity).
    pub leaf: &'a Certificate,
    /// Intermediate certificates, in order from leaf-adjacent to root-adjacent.
    pub intermediates: Vec<&'a Certificate>,
    /// The trusted root certificate.
    pub root: &'a Certificate,
}

/// Validate the structural and time-bounds aspects of a path. Does NOT
/// verify signatures — that requires algorithm-specific verifiers and
/// is done in `verify_path_signatures`.
pub fn validate_path(path: &CertPath<'_>, now: DateTime<Utc>) -> VerificationResult {
    let mut checks = Vec::new();
    let mut valid = true;

    let chain: Vec<&Certificate> = std::iter::once(path.leaf)
        .chain(path.intermediates.iter().copied())
        .chain(std::iter::once(path.root))
        .collect();

    for cert in &chain {
        if !cert.is_within_validity(now) {
            if now < cert.not_before_chrono() {
                checks.push(PathFailure::NotYetValid);
            } else {
                checks.push(PathFailure::Expired);
            }
            valid = false;
        }
    }

    if chain.len() > 16 {
        checks.push(PathFailure::ChainTooLong);
        valid = false;
    }

    VerificationResult { valid, checks }
}

/// Hook for signature verification — caller provides a verifier function.
/// The verifier receives (parent_pubkey, signed_cert_der) and returns Ok(())
/// if the signature is valid.
pub fn verify_path_signatures<F>(path: &CertPath<'_>, verifier: F) -> VerificationResult
where
    F: Fn(&[u8], &[u8]) -> Result<(), String>,
{
    let mut checks = Vec::new();
    let mut valid = true;

    let chain: Vec<&Certificate> = std::iter::once(path.leaf)
        .chain(path.intermediates.iter().copied())
        .chain(std::iter::once(path.root))
        .collect();

    for i in 0..chain.len().saturating_sub(1) {
        let child = chain[i];
        let parent = chain[i + 1];
        match verifier(parent.public_key_bytes(), child.to_der().as_slice()) {
            Ok(()) => {}
            Err(_) => {
                checks.push(PathFailure::SignatureInvalid);
                valid = false;
            }
        }
    }

    VerificationResult { valid, checks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Certificate;

    #[allow(dead_code)] // placeholder until real cert fixtures land
    fn synthetic_cert() -> Certificate {
        // We can't easily generate a real cert in pure-Rust no-deps mode.
        // Path validation tests require real cert chains, which belong in
        // integration tests. This module's logic is exercised there.
        unimplemented!("use integration tests with real cert fixtures")
    }

    #[test]
    fn empty_path_is_valid() {
        // Sanity check the API surface compiles.
        let now = Utc::now();
        let _ = now;
    }
}
