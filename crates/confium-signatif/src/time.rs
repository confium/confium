//! The time dimension: external time anchoring (SIGNATIF §8.8).
//!
//! The time dimension is attested by a **time key** — a co-signature
//! from a time authority recording that the artifact hash existed at a
//! stated time, anchored to an external, irrefutable time source
//! (OpenTimestamps commitments in Confium). The signer's self-asserted
//! timestamp is never the sole evidence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{SignatifError, SignatifResult};
use crate::graph::SignatureVerifier;
use crate::jcs;

/// A time authority's attestation over an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeAttestation {
    /// The time authority's identifier.
    pub authority: String,
    /// The artifact's canonical payload hash (hex).
    pub artifact_hash: String,
    /// When the authority attests the artifact existed.
    pub attested_at: DateTime<Utc>,
    /// The external anchor: serialized OpenTimestamps proof (or
    /// equivalent) binding the hash to an irrefutable time source.
    pub external_anchor: Vec<u8>,
    /// The time authority's signature over the attestation body.
    pub signature: Vec<u8>,
}

impl TimeAttestation {
    /// The canonical signing bytes.
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn signing_bytes(&self) -> SignatifResult<Vec<u8>> {
        let v = serde_json::json!({
            "authority": self.authority,
            "artifact_hash": self.artifact_hash,
            "attested_at": self.attested_at.to_rfc3339(),
            "external_anchor": hex::encode(&self.external_anchor),
        });
        Ok(jcs::canonicalize(&v)?.into_bytes())
    }

    /// Verify the attestation: the authority's signature, and that an
    /// external anchor is present (the anchor itself is verified
    /// against the time source by the OTS layer).
    ///
    /// # Errors
    ///
    /// Signature or anchor errors.
    pub fn verify(
        &self,
        authority_key: &[u8],
        verifier: &dyn SignatureVerifier,
    ) -> SignatifResult<()> {
        if self.external_anchor.is_empty() {
            return Err(SignatifError::BadSignature {
                context: "time attestation lacks an external anchor".into(),
            });
        }
        let msg = self.signing_bytes()?;
        if !verifier.verify(authority_key, &msg, &self.signature) {
            return Err(SignatifError::BadSignature {
                context: format!("time authority {}", self.authority),
            });
        }
        Ok(())
    }

    /// Freshness against a window: fresh inside `window`, stale
    /// (downgrade) inside `window + grace`, rejected beyond.
    pub fn freshness(
        &self,
        now: DateTime<Utc>,
        window: chrono::Duration,
        grace: chrono::Duration,
    ) -> TimeFreshness {
        let age = now.signed_duration_since(self.attested_at);
        if age <= window {
            TimeFreshness::Fresh
        } else if age <= window + grace {
            TimeFreshness::Stale
        } else {
            TimeFreshness::Expired
        }
    }
}

/// Freshness outcome for the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeFreshness {
    /// Inside the window.
    Fresh,
    /// Inside the grace period — downgrade.
    Stale,
    /// Beyond grace — reject.
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn generate_key() -> ed25519_dalek::SigningKey {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    struct Ed25519Verifier;

    impl SignatureVerifier for Ed25519Verifier {
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

    fn attestation() -> (TimeAttestation, ed25519_dalek::SigningKey) {
        let sk = generate_key();
        let mut a = TimeAttestation {
            authority: "time-authority-1".into(),
            artifact_hash: hex::encode([1u8; 32]),
            attested_at: Utc::now(),
            external_anchor: b"ots-proof".to_vec(),
            signature: vec![],
        };
        a.signature = sk.sign(&a.signing_bytes().unwrap()).to_bytes().to_vec();
        (a, sk)
    }

    #[test]
    fn verifies_with_external_anchor() {
        let (a, sk) = attestation();
        assert!(
            a.verify(sk.verifying_key().as_bytes(), &Ed25519Verifier)
                .is_ok()
        );
        let mut stripped = a.clone();
        stripped.external_anchor = vec![];
        assert!(
            stripped
                .verify(sk.verifying_key().as_bytes(), &Ed25519Verifier)
                .is_err()
        );
    }

    #[test]
    fn freshness_ladder() {
        let (mut a, _) = attestation();
        let window = chrono::Duration::minutes(5);
        let grace = chrono::Duration::minutes(5);
        a.attested_at = Utc::now() - chrono::Duration::minutes(1);
        assert_eq!(a.freshness(Utc::now(), window, grace), TimeFreshness::Fresh);
        a.attested_at = Utc::now() - chrono::Duration::minutes(8);
        assert_eq!(a.freshness(Utc::now(), window, grace), TimeFreshness::Stale);
        a.attested_at = Utc::now() - chrono::Duration::minutes(30);
        assert_eq!(
            a.freshness(Utc::now(), window, grace),
            TimeFreshness::Expired
        );
    }
}
