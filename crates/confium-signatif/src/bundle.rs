//! Trust anchor bundles (SIGNATIF §7, Annex E).
//!
//! The bundle is the starting point of all verification paths: the set
//! of root trust authorities (with aggregate keys and quorum
//! parameters) and the recognized transparency logs. It is versioned,
//! validity-bounded, signed by the root authority, deterministic for
//! out-of-band distribution, and — per the framework — its updates are
//! recorded in a transparency log.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{SignatifError, SignatifResult};
use crate::graph::Quorum;
use crate::jcs;

/// One root trust authority in the bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRoot {
    /// Human-readable root name.
    pub name: String,
    /// The root's aggregate public key (SPKI or raw verifier bytes).
    pub aggregate_key: Vec<u8>,
    /// SHA-256 fingerprint of the aggregate key (hex).
    pub fingerprint: String,
    /// Quorum parameters of the root authority.
    pub quorum: Option<Quorum>,
}

/// One recognized transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorLog {
    /// Log name.
    pub name: String,
    /// The log operator's public key (verifies signed tree heads).
    pub operator_key: Vec<u8>,
    /// Log endpoint (primary or mirror).
    pub endpoint: String,
}

/// A versioned, signed set of trust anchors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorBundle {
    /// Version identifier (e.g. "2026.08").
    pub bundle_version: String,
    /// Bundle validity start.
    pub valid_from: DateTime<Utc>,
    /// Bundle validity end.
    pub valid_until: DateTime<Utc>,
    /// Root trust authorities.
    pub roots: Vec<AnchorRoot>,
    /// Recognized transparency logs and mirrors.
    pub transparency_logs: Vec<AnchorLog>,
    /// The transparency-log reference recording this bundle update
    /// (§7: bundle updates shall be recorded in a transparency log).
    /// Signed as part of the bundle body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_log: Option<crate::discovery::LogRef>,
    /// Threshold signature of the issuing root over the canonical
    /// bundle body (all fields except this signature).
    pub bundle_signature: Vec<u8>,
}

impl TrustAnchorBundle {
    /// The canonical bytes covered by the bundle signature: JCS of the
    /// bundle with `bundle_signature` cleared.
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn signing_bytes(&self) -> SignatifResult<Vec<u8>> {
        let mut copy = self.clone();
        copy.bundle_signature = Vec::new();
        Ok(
            jcs::canonicalize(&serde_json::to_value(&copy).expect("bundle serializes"))?
                .into_bytes(),
        )
    }

    /// Verify the bundle signature against the root whose key it was
    /// produced with, and the validity period at `now`.
    ///
    /// # Errors
    ///
    /// [`SignatifError::BadSignature`] when no root key verifies the
    /// signature; [`SignatifError::BundleValidity`] outside the
    /// validity window.
    pub fn verify(
        &self,
        now: DateTime<Utc>,
        verifier: &dyn crate::graph::SignatureVerifier,
    ) -> SignatifResult<()> {
        if now < self.valid_from || now > self.valid_until {
            return Err(SignatifError::BundleValidity);
        }
        let msg = self.signing_bytes()?;
        if self.roots.is_empty() {
            return Err(SignatifError::BadSignature {
                context: "anchor bundle has no roots".into(),
            });
        }
        if self
            .roots
            .iter()
            .any(|r| verifier.verify(&r.aggregate_key, &msg, &self.bundle_signature))
        {
            return Ok(());
        }
        Err(SignatifError::BadSignature {
            context: "anchor bundle signature".into(),
        })
    }

    /// Whether `root_key` belongs to one of the bundle's roots — used
    /// by path-finding to decide path termination.
    pub fn matches_root(&self, root_key: &[u8]) -> bool {
        self.roots.iter().any(|r| r.aggregate_key == root_key)
    }

    /// The root whose aggregate key equals `root_key`, if any.
    pub fn root_by_key(&self, root_key: &[u8]) -> Option<&AnchorRoot> {
        self.roots.iter().find(|r| r.aggregate_key == root_key)
    }

    /// Deterministic distribution bytes (JCS of the full bundle).
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn distribution_bytes(&self) -> SignatifResult<Vec<u8>> {
        Ok(
            jcs::canonicalize(&serde_json::to_value(self).expect("bundle serializes"))?
                .into_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::AcceptAllVerifier;
    use ed25519_dalek::Signer;

    fn generate_key() -> ed25519_dalek::SigningKey {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    struct Ed25519Verifier;

    impl crate::graph::SignatureVerifier for Ed25519Verifier {
        fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            use ed25519_dalek::Signature;
            use ed25519_dalek::Verifier;
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk.try_into().unwrap()) else {
                return false;
            };
            let Ok(signature) = Signature::from_slice(sig) else {
                return false;
            };
            vk.verify(msg, &signature).is_ok()
        }
    }

    #[test]
    fn bundle_signs_and_verifies() {
        let sk = generate_key();
        let pk = sk.verifying_key().as_bytes().to_vec();
        let mut bundle = TrustAnchorBundle {
            bundle_version: "2026.08".into(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::days(30),
            roots: vec![AnchorRoot {
                name: "root".into(),
                aggregate_key: pk,
                fingerprint: "00".into(),
                quorum: None,
            }],
            transparency_logs: Vec::new(),
            bundle_signature: Vec::new(),
            update_log: None,
        };
        bundle.bundle_signature = sk
            .sign(&bundle.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        assert!(bundle.verify(Utc::now(), &Ed25519Verifier).is_ok());
        bundle.bundle_signature[3] ^= 1;
        assert!(bundle.verify(Utc::now(), &Ed25519Verifier).is_err());
    }

    #[test]
    fn update_log_reference_is_signed_content() {
        let sk = generate_key();
        let mut bundle = TrustAnchorBundle {
            bundle_version: "2026.09".into(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::days(30),
            roots: vec![AnchorRoot {
                name: "root".into(),
                aggregate_key: sk.verifying_key().as_bytes().to_vec(),
                fingerprint: "00".into(),
                quorum: None,
            }],
            transparency_logs: Vec::new(),
            update_log: Some(crate::discovery::LogRef {
                log: "nmi-log".into(),
                sequence: 4242,
            }),
            bundle_signature: Vec::new(),
        };
        bundle.bundle_signature = sk
            .sign(&bundle.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        assert!(bundle.verify(Utc::now(), &Ed25519Verifier).is_ok());
        // Flipping the log reference breaks the signature: it is
        // signed content.
        bundle.update_log.as_mut().unwrap().sequence = 4243;
        assert!(bundle.verify(Utc::now(), &Ed25519Verifier).is_err());
    }

    #[test]
    fn expired_bundle_fails() {
        let b = TrustAnchorBundle {
            bundle_version: "1".into(),
            valid_from: Utc::now() - chrono::Duration::days(30),
            valid_until: Utc::now() - chrono::Duration::days(1),
            roots: vec![],
            transparency_logs: vec![],
            bundle_signature: vec![],
            update_log: None,
        };
        assert!(matches!(
            b.verify(Utc::now(), &AcceptAllVerifier),
            Err(SignatifError::BundleValidity)
        ));
    }
}
