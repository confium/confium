//! Signature verification.
//!
//! For v1 the registry client does not yet perform real PGP signature
//! verification. This module implements the policy check — "is at least
//! one signature from a trusted publisher?" — over the list of signer
//! names the manifest claims. Real PGP verification (fetching the
//! publisher's `.asc`, checking the detached signature against the
//! artifact bytes) is a follow-up tracked separately.
//!
//! The policy layer is intentionally separated from the cryptographic
//! layer so that wiring in real verification later only changes how
//! `signers` is derived, not how the trust decision is made.

use crate::error::{Error, Result};
use crate::trust::TrustStore;

/// The outcome of a signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// At least one `signer` matched a trusted publisher.
    Verified { signers: Vec<String> },
    /// No trusted publisher signed the artifact. The caller may still
    /// proceed if `allow_untrusted` is set (development escape hatch).
    Unverified { signers: Vec<String> },
}

impl Verification {
    /// True if the artifact passed the trust policy.
    pub fn is_verified(&self) -> bool {
        matches!(self, Verification::Verified { .. })
    }

    /// The publisher names that signed the artifact (regardless of
    /// whether any were trusted).
    pub fn signers(&self) -> &[String] {
        match self {
            Verification::Verified { signers } | Verification::Unverified { signers } => signers,
        }
    }
}

/// Apply the trust policy: the artifact is trusted iff at least one of
/// `signers` is present in `trust`. Returns
/// [`Error::UntrustedPlugin`] when unverified and `allow_untrusted` is
/// false.
pub fn check(
    plugin_name: &str,
    signers: &[String],
    trust: &TrustStore,
    allow_untrusted: bool,
) -> Result<Verification> {
    let any_trusted = signers.iter().any(|s| trust.is_trusted(s).unwrap_or(false));
    if any_trusted {
        Ok(Verification::Verified {
            signers: signers.to_vec(),
        })
    } else if allow_untrusted {
        Ok(Verification::Unverified {
            signers: signers.to_vec(),
        })
    } else {
        Err(Error::UntrustedPlugin {
            name: plugin_name.to_string(),
            signers: signers.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::TrustRoot;
    use tempfile::tempdir;

    fn root(name: &str) -> TrustRoot {
        TrustRoot {
            name: name.to_string(),
            key_id: "0x1".to_string(),
            fingerprint: "AAAA".to_string(),
            key_url: format!("/publishers/{}.asc", name),
        }
    }

    #[test]
    fn verifies_when_trusted_signer_present() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        store.put(&root("ribose")).unwrap();
        let v = check("botan", &["ribose".to_string()], &store, false).unwrap();
        assert!(v.is_verified());
    }

    #[test]
    fn refuses_untrusted_without_override() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let err = check("botan", &["stranger".to_string()], &store, false).unwrap_err();
        assert!(matches!(err, Error::UntrustedPlugin { .. }));
    }

    #[test]
    fn allows_untrusted_with_override() {
        let dir = tempdir().unwrap();
        let store = TrustStore::open(dir.path()).unwrap();
        let v = check("botan", &["stranger".to_string()], &store, true).unwrap();
        assert!(!v.is_verified());
        assert_eq!(v.signers(), &["stranger"]);
    }
}
