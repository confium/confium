//! Composite multi-algorithm signature aggregation.
//!
//! Combines classical (Ed25519, ECDSA) and PQ (ML-DSA, SLH-DSA)
//! signatures so that breaking either alone doesn't break the
//! composite. Used for PQ migration without breaking verifiers.
//!
//! See `TODO.roadmap/35-pq-composite-signatures.md` for the full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Algorithm identifier for Ed25519 components.
pub const ED25519: &str = "Ed25519";
/// Algorithm identifier for ML-DSA-65 components (placeholder; no real verifier).
pub const ML_DSA_65: &str = "ML-DSA-65";

/// A single component of a composite signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentSignature {
    /// Algorithm identifier (e.g., "Ed25519", "ML-DSA-65").
    pub algorithm: String,
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// A composite signature — multiple components over the same message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeSignature {
    /// Component signatures.
    pub components: Vec<ComponentSignature>,
}

/// Errors during composite signature operations.
#[derive(Debug, thiserror::Error)]
pub enum CompositeError {
    /// Verification failed (at least one component invalid).
    #[error("verification failed: {0}")]
    Verify(String),
    /// No components.
    #[error("composite signature has no components")]
    Empty,
    /// Serialization error.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl CompositeSignature {
    /// Build a composite from components.
    pub fn new(components: Vec<ComponentSignature>) -> Self {
        Self { components }
    }

    /// Number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// List the algorithm identifiers.
    pub fn algorithms(&self) -> Vec<&str> {
        self.components.iter().map(|c| c.algorithm.as_str()).collect()
    }

    /// Verify all components. Caller provides the verifier function:
    /// (algorithm, public_key, message, signature) → Result<(), String>.
    pub fn verify<F>(
        &self,
        message: &[u8],
        verifier: F,
    ) -> Result<VerificationResult, CompositeError>
    where
        F: Fn(&str, &[u8], &[u8], &[u8]) -> Result<(), String>,
    {
        if self.components.is_empty() {
            return Err(CompositeError::Empty);
        }
        let mut per_component = Vec::new();
        let mut all_ok = true;
        for (i, c) in self.components.iter().enumerate() {
            match verifier(&c.algorithm, &c.public_key, message, &c.signature) {
                Ok(()) => per_component.push(ComponentResult {
                    index: i,
                    algorithm: c.algorithm.clone(),
                    verified: true,
                    error: None,
                }),
                Err(e) => {
                    all_ok = false;
                    per_component.push(ComponentResult {
                        index: i,
                        algorithm: c.algorithm.clone(),
                        verified: false,
                        error: Some(e),
                    });
                }
            }
        }
        Ok(VerificationResult {
            all_verified: all_ok,
            per_component,
        })
    }
}

/// Per-component verification result.
#[derive(Debug, Clone)]
pub struct ComponentResult {
    /// Index in components vector.
    pub index: usize,
    /// Algorithm.
    pub algorithm: String,
    /// Whether this component verified.
    pub verified: bool,
    /// Error message if verification failed.
    pub error: Option<String>,
}

/// Aggregate verification result.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// True iff every component verified.
    pub all_verified: bool,
    /// Per-component results.
    pub per_component: Vec<ComponentResult>,
}

/// Standard composite algorithm IDs per IETF LAMPS COMPOSITE SIG draft.
pub mod algorithm_ids {
    /// Ed25519 + ML-DSA-65 composite.
    pub const ED25519_MLDSA65: &str = "id-MLDSA65-Ed25519";
    /// ECDSA-P256 + ML-DSA-65 composite.
    pub const ECDSAP256_MLDSA65: &str = "id-MLDSA65-ECDSA-P256";
    /// ECDSA-P384 + ML-DSA-87 composite.
    pub const ECDSAP384_MLDSA87: &str = "id-MLDSA87-ECDSA-P384";
    /// Ed25519 + SLH-DSA-128s composite.
    pub const ED25519_SLHDSA128S: &str = "id-SLHDSA-SHA2-128S-Ed25519";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_round_trip() {
        let composite = CompositeSignature::new(vec![
            ComponentSignature {
                algorithm: "Ed25519".into(),
                public_key: vec![1u8; 32],
                signature: vec![2u8; 64],
            },
            ComponentSignature {
                algorithm: "ML-DSA-65".into(),
                public_key: vec![3u8; 1952],
                signature: vec![4u8; 3309],
            },
        ]);
        assert_eq!(composite.component_count(), 2);

        let result = composite
            .verify(b"hello", |_, _, _, _| Ok(()))
            .unwrap();
        assert!(result.all_verified);
    }

    #[test]
    fn composite_fails_if_any_component_fails() {
        let composite = CompositeSignature::new(vec![
            ComponentSignature {
                algorithm: "Ed25519".into(),
                public_key: vec![1u8; 32],
                signature: vec![2u8; 64],
            },
            ComponentSignature {
                algorithm: "ML-DSA-65".into(),
                public_key: vec![3u8; 1952],
                signature: vec![4u8; 3309],
            },
        ]);
        let result = composite
            .verify(b"hello", |alg, _, _, _| {
                if alg == "Ed25519" {
                    Ok(())
                } else {
                    Err("bad".into())
                }
            })
            .unwrap();
        assert!(!result.all_verified);
    }

    #[test]
    fn empty_composite_errors() {
        let composite = CompositeSignature::new(vec![]);
        let result = composite.verify(b"x", |_, _, _, _| Ok(()));
        assert!(matches!(result, Err(CompositeError::Empty)));
    }
}

/// Real Ed25519 verifier. Use as the verifier callback when the composite
/// contains an Ed25519 component. Returns Ok if the Ed25519 component verifies.
pub fn ed25519_verifier(
    algorithm: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if algorithm != ED25519 {
        return Err(format!("not Ed25519: {algorithm}"));
    }
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "Ed25519 pubkey must be 32 bytes".to_string())?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| "Ed25519 sig must be 64 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| format!("bad pubkey: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig).map_err(|e| format!("verify: {e}"))
}

/// Build a real Ed25519 component signature. Used for testing and as a
/// reference for plugin authors.
pub fn build_ed25519_component(
    signing_key: &ed25519_dalek::SigningKey,
    message: &[u8],
) -> Result<ComponentSignature, CompositeError> {
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(message);
    Ok(ComponentSignature {
        algorithm: ED25519.into(),
        public_key: signing_key.verifying_key().to_bytes().to_vec(),
        signature: sig.to_bytes().to_vec(),
    })
}

#[cfg(test)]
mod real_ed25519_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn real_ed25519_round_trip() {
        let signing = SigningKey::generate(&mut OsRng);
        let message = b"composite signature test message";
        let component = build_ed25519_component(&signing, message).unwrap();
        let result = ed25519_verifier(
            &component.algorithm,
            &component.public_key,
            message,
            &component.signature,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn real_ed25519_rejects_wrong_message() {
        let signing = SigningKey::generate(&mut OsRng);
        let component = build_ed25519_component(&signing, b"original").unwrap();
        let result = ed25519_verifier(
            &component.algorithm,
            &component.public_key,
            b"different",
            &component.signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn composite_with_real_ed25519_verifies() {
        let signing = SigningKey::generate(&mut OsRng);
        let message = b"composite with real crypto";
        let component = build_ed25519_component(&signing, message).unwrap();
        let composite = CompositeSignature::new(vec![component]);
        let result = composite
            .verify(message, |alg, pk, msg, sig| {
                ed25519_verifier(alg, pk, msg, sig)
            })
            .unwrap();
        assert!(result.all_verified);
        assert_eq!(result.per_component.len(), 1);
    }

    #[test]
    fn composite_with_real_ed25519_plus_mock_ml_dsa() {
        let signing = SigningKey::generate(&mut OsRng);
        let message = b"PQ migration composite";
        let ed_component = build_ed25519_component(&signing, message).unwrap();
        // Mock ML-DSA component (always verifies for now)
        let ml_component = ComponentSignature {
            algorithm: ML_DSA_65.into(),
            public_key: vec![0u8; 1952],
            signature: vec![0u8; 3309],
        };
        let composite = CompositeSignature::new(vec![ed_component, ml_component]);
        let result = composite
            .verify(message, |alg, pk, msg, sig| {
                if alg == ED25519 {
                    ed25519_verifier(alg, pk, msg, sig)
                } else if alg == ML_DSA_65 {
                    Ok(())
                } else {
                    Err(format!("unknown algorithm: {alg}"))
                }
            })
            .unwrap();
        assert!(result.all_verified);
        assert_eq!(result.per_component.len(), 2);
    }
}
