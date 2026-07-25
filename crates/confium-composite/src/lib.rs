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
