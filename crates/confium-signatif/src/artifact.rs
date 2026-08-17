//! Trusted artifacts and dimension-tagged co-signatures (SIGNATIF §8).
//!
//! A [`TrustedArtifact`] is the convergence point of independent
//! attestations: every [`CoSignatureBlock`] — regardless of trust
//! dimension, organization, or trust chain — signs the **same**
//! canonical payload hash. Partial attestation is not conforming, a
//! co-signature cannot be stripped without breaking self-description,
//! and each block binds to the artifact identifier so blocks cannot be
//! replayed onto a different artifact (the `replay-protection`
//! requirement).
//!
//! Artifacts are *living*: dimension attestations accumulate over time
//! ([`TrustedArtifact::add_attestation`]) while the original canonical
//! payload hash stays fixed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{SignatifError, SignatifResult};
use crate::graph::SignatureVerifier;
use crate::jcs;
use crate::registry::{DimensionTag, Registry};

/// Semantic version of the artifact format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVersion {
    /// Breaking changes — verifiers reject higher majors.
    pub major: u32,
    /// Backward/forward compatible additions — unknown fields ignored.
    pub minor: u32,
}

impl ArtifactVersion {
    /// Whether a verifier supporting `(self)` can process `other`:
    /// same or lower major, any minor.
    pub fn accepts(&self, other: &ArtifactVersion) -> bool {
        other.major <= self.major
    }
}

impl std::fmt::Display for ArtifactVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// One independent attestation on the artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoSignatureBlock {
    /// The trust dimension this block attests.
    pub dimension: DimensionTag,
    /// Signing algorithm identifier (from the algorithm registry).
    pub algorithm: String,
    /// End-certificate reference: a transparency-log sequence pointer
    /// or a key fingerprint.
    pub signer_cert_ref: String,
    /// The signer's public key (SPKI bytes).
    pub signer_pubkey: Vec<u8>,
    /// Reference to the signer's root — may differ per block
    /// (cross-domain fusion needs no root cross-recognition).
    pub chain_ref: String,
    /// The signature over the co-signature signing input.
    pub signature: Vec<u8>,
    /// When this attestation was produced.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// A trusted artifact: payload + dimension attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedArtifact {
    /// Artifact format version.
    pub version: ArtifactVersion,
    /// Unique artifact identifier — bound into every co-signature to
    /// prevent replay onto other artifacts.
    pub artifact_id: String,
    /// The domain payload (schema identified by `$payload_schema`).
    pub payload: Value,
    /// URI identifying the payload schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_schema: Option<String>,
    /// SHA-256 of the JCS canonicalization of the payload.
    pub canonical_payload_hash: [u8; 32],
    /// The dimension attestations converging on this artifact.
    pub co_signatures: Vec<CoSignatureBlock>,
}

impl TrustedArtifact {
    /// Create a new artifact, computing the canonical payload hash.
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn new(
        version: ArtifactVersion,
        artifact_id: impl Into<String>,
        payload: Value,
        payload_schema: Option<String>,
    ) -> SignatifResult<Self> {
        let canonical_payload_hash = jcs::canonical_hash(&payload)?;
        Ok(Self {
            version,
            artifact_id: artifact_id.into(),
            payload,
            payload_schema,
            canonical_payload_hash,
            co_signatures: Vec::new(),
        })
    }

    /// The signing input for a co-signature: artifact identity bound to
    /// the canonical payload hash, so blocks are artifact-specific and
    /// cannot be replayed across artifacts.
    pub fn cosign_input(&self, dimension: &DimensionTag) -> Vec<u8> {
        let mut bytes = self.artifact_id.as_bytes().to_vec();
        bytes.push(0x00);
        bytes.extend_from_slice(&self.canonical_payload_hash);
        bytes.push(0x00);
        bytes.extend_from_slice(dimension.as_str().as_bytes());
        bytes
    }

    /// Produce a co-signature over this artifact (helper for signers).
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &mut self,
        dimension: DimensionTag,
        algorithm: impl Into<String>,
        signer_cert_ref: impl Into<String>,
        signer_pubkey: Vec<u8>,
        chain_ref: impl Into<String>,
        signer: &dyn Fn(&[u8]) -> Vec<u8>,
        registry: &Registry,
    ) -> SignatifResult<()> {
        if !registry.dimensions.contains(dimension.as_str()) {
            return Err(SignatifError::Registry {
                registry: "trust-dimension".into(),
                entry: dimension.as_str().to_string(),
            });
        }
        let algorithm = algorithm.into();
        registry
            .algorithms
            .usable(&algorithm)
            .ok_or_else(|| SignatifError::Registry {
                registry: "algorithm".into(),
                entry: algorithm.clone(),
            })?;
        let input = self.cosign_input(&dimension);
        let signature = signer(&input);
        self.co_signatures.push(CoSignatureBlock {
            dimension,
            algorithm,
            signer_cert_ref: signer_cert_ref.into(),
            signer_pubkey,
            chain_ref: chain_ref.into(),
            signature,
            timestamp: chrono::Utc::now(),
        });
        Ok(())
    }

    /// Living artifacts: add a dimension attestation. The block must
    /// sign the *original* canonical payload hash — enforced because
    /// the signing input derives from the fixed hash and artifact id.
    ///
    /// # Errors
    ///
    /// Returns a registry error for unknown dimensions or unusable
    /// algorithms.
    pub fn add_attestation(
        &mut self,
        block: CoSignatureBlock,
        registry: &Registry,
    ) -> SignatifResult<()> {
        if !registry.dimensions.contains(block.dimension.as_str()) {
            return Err(SignatifError::Registry {
                registry: "trust-dimension".into(),
                entry: block.dimension.as_str().to_string(),
            });
        }
        registry
            .algorithms
            .usable(&block.algorithm)
            .ok_or_else(|| SignatifError::Registry {
                registry: "algorithm".into(),
                entry: block.algorithm.clone(),
            })?;
        self.co_signatures.push(block);
        Ok(())
    }

    /// Verify the artifact's self-consistency: the recorded canonical
    /// payload hash equals the hash of the current payload (detects
    /// any post-signing payload modification — signature wrapping
    /// prevention), and every block is verified independently against
    /// its own public key.
    ///
    /// # Errors
    ///
    /// [`SignatifError::ArtifactFormat`] on hash mismatch or an
    /// unknown/retired algorithm; [`SignatifError::BadSignature`] when
    /// a block fails to verify.
    pub fn verify_self(
        &self,
        registry: &Registry,
        verifier: &dyn SignatureVerifier,
    ) -> SignatifResult<()> {
        let recomputed = jcs::canonical_hash(&self.payload)?;
        if recomputed != self.canonical_payload_hash {
            return Err(SignatifError::ArtifactFormat(
                "payload does not match canonical_payload_hash (signed content != processed content)"
                    .into(),
            ));
        }
        for block in &self.co_signatures {
            registry
                .algorithms
                .usable(&block.algorithm)
                .ok_or_else(|| SignatifError::Registry {
                    registry: "algorithm".into(),
                    entry: block.algorithm.clone(),
                })?;
            let input = self.cosign_input(&block.dimension);
            if !verifier.verify(&block.signer_pubkey, &input, &block.signature) {
                return Err(SignatifError::BadSignature {
                    context: format!(
                        "co-signature dimension={} signer={}",
                        block.dimension.as_str(),
                        block.signer_cert_ref
                    ),
                });
            }
        }
        Ok(())
    }

    /// The distinct dimensions attested by currently-valid blocks.
    pub fn dimensions_verified(&self) -> Vec<DimensionTag> {
        let mut seen = std::collections::BTreeSet::new();
        for b in &self.co_signatures {
            seen.insert(b.dimension.clone());
        }
        seen.into_iter().collect()
    }

    /// The distinct chain (root) references across blocks — feeds the
    /// coverage report's independent-root count.
    pub fn distinct_roots(&self) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        for b in &self.co_signatures {
            seen.insert(b.chain_ref.clone());
        }
        seen.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

    fn generate_key() -> ed25519_dalek::SigningKey {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    struct Ed25519Verifier;

    impl SignatureVerifier for Ed25519Verifier {
        fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk.try_into().unwrap()) else {
                return false;
            };
            let Ok(signature) = Signature::from_slice(sig) else {
                return false;
            };
            vk.verify(msg, &signature).is_ok()
        }
    }

    fn sample(registry: &Registry) -> (TrustedArtifact, SigningKey) {
        let sk = generate_key();
        let mut art = TrustedArtifact::new(
            ArtifactVersion { major: 1, minor: 0 },
            "art-2026-00001",
            serde_json::json!({"batch_id": "LOT-2026-001", "quantity": 50000}),
            Some("https://example.cnml/schema/vaccine-batch.json".into()),
        )
        .unwrap();
        let pk = sk.verifying_key().as_bytes().to_vec();
        art.sign(
            DimensionTag::data(),
            "Ed25519",
            "transparency-log-seq:12345",
            pk.clone(),
            "root-cnml",
            &|m| sk.sign(m).to_bytes().to_vec(),
            registry,
        )
        .unwrap();
        (art, sk)
    }

    #[test]
    fn create_sign_and_verify() {
        let registry = Registry::with_initial_values();
        let (art, _) = sample(&registry);
        assert!(art.verify_self(&registry, &Ed25519Verifier).is_ok());
        assert_eq!(art.dimensions_verified(), vec![DimensionTag::data()]);
        assert_eq!(art.distinct_roots(), vec!["root-cnml".to_string()]);
    }

    #[test]
    fn payload_tampering_detected() {
        let registry = Registry::with_initial_values();
        let (mut art, _) = sample(&registry);
        art.payload["quantity"] = serde_json::json!(1);
        assert!(art.verify_self(&registry, &Ed25519Verifier).is_err());
    }

    #[test]
    fn replay_across_artifacts_fails() {
        let registry = Registry::with_initial_values();
        let (art, sk) = sample(&registry);
        // A second artifact with different id: the stolen block signs
        // the first artifact's id+hash, so it fails here.
        let mut other = TrustedArtifact::new(
            ArtifactVersion { major: 1, minor: 0 },
            "art-2026-00002",
            serde_json::json!({"batch_id": "LOT-2026-001", "quantity": 50000}),
            None,
        )
        .unwrap();
        let stolen = art.co_signatures[0].clone();
        other.co_signatures.push(stolen);
        assert!(other.verify_self(&registry, &Ed25519Verifier).is_err());
        let _ = sk;
    }

    #[test]
    fn living_artifact_accumulates_dimensions() {
        let registry = Registry::with_initial_values();
        let (mut art, _) = sample(&registry);
        let person = generate_key();
        let before_hash = art.canonical_payload_hash;
        art.sign(
            DimensionTag::person(),
            "Ed25519",
            "operator-key-fingerprint",
            person.verifying_key().as_bytes().to_vec(),
            "root-cnml",
            &|m| person.sign(m).to_bytes().to_vec(),
            &registry,
        )
        .unwrap();
        assert_eq!(art.canonical_payload_hash, before_hash);
        assert!(art.verify_self(&registry, &Ed25519Verifier).is_ok());
        assert_eq!(art.dimensions_verified().len(), 2);
    }

    #[test]
    fn unknown_dimension_rejected_via_registry() {
        let registry = Registry::with_initial_values();
        let (mut art, _) = sample(&registry);
        let err = art
            .sign(
                DimensionTag::custom("no-such-dimension"),
                "Ed25519",
                "x",
                vec![0u8; 32],
                "r",
                &|_| vec![0u8; 64],
                &registry,
            )
            .unwrap_err();
        assert!(matches!(err, SignatifError::Registry { .. }));
    }

    #[test]
    fn version_compatibility() {
        let v1 = ArtifactVersion { major: 1, minor: 3 };
        assert!(v1.accepts(&ArtifactVersion { major: 1, minor: 0 }));
        assert!(v1.accepts(&ArtifactVersion { major: 1, minor: 9 }));
        assert!(!v1.accepts(&ArtifactVersion { major: 2, minor: 0 }));
    }
}
