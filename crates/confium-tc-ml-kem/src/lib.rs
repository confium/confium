//! Threshold ML-KEM (FIPS 203) — research prototype.
//!
//! **No production-quality threshold ML-KEM exists today.** This crate
//! is a research prototype. Production use requires academic collaborator
//! engagement (see `TODO.roadmap/26`).
//!
//! Research questions:
//! - Proactive share refresh for lattice schemes
//! - Threshold decryption ceremony with audit trail
//! - Re-encryption for quorum composition changes
//! - Composition with AEAD for symmetric encryption
//! - Cross-tier re-encryption (IA → BIML without plaintext exposure)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// ML-KEM parameter sets (FIPS 203).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParameterSet {
    /// ML-KEM-512 (NIST Level 1 / AES-128 equivalent).
    MlKem512,
    /// ML-KEM-768 (NIST Level 3 / AES-192 equivalent). Recommended default.
    MlKem768,
    /// ML-KEM-1024 (NIST Level 5 / AES-256 equivalent).
    MlKem1024,
}

impl ParameterSet {
    /// Public key size in bytes for this parameter set.
    pub fn public_key_size(&self) -> usize {
        match self {
            ParameterSet::MlKem512 => 800,
            ParameterSet::MlKem768 => 1184,
            ParameterSet::MlKem1024 => 1568,
        }
    }

    /// Ciphertext (encapsulated key) size.
    pub fn ciphertext_size(&self) -> usize {
        match self {
            ParameterSet::MlKem512 => 768,
            ParameterSet::MlKem768 => 1088,
            ParameterSet::MlKem1024 => 1568,
        }
    }

    /// Shared secret size (always 32 bytes).
    pub fn shared_secret_size(&self) -> usize {
        32
    }
}

/// Threshold ML-KEM public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdPublicKey {
    /// Parameter set.
    pub params: ParameterSet,
    /// Public key bytes.
    pub bytes: Vec<u8>,
}

/// Share of the threshold ML-KEM secret key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Parameter set.
    pub params: ParameterSet,
    /// Party index.
    pub party_index: u32,
    /// Share bytes.
    pub bytes: Vec<u8>,
}

/// Errors during threshold ML-KEM operations.
#[derive(Debug, thiserror::Error)]
pub enum MlKemError {
    /// Parameter mismatch.
    #[error("parameter set mismatch")]
    ParamMismatch,
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Have count.
        have: usize,
        /// Need count.
        need: u32,
    },
    /// Research-only operation.
    #[error("operation requires research collaborator engagement: {0}")]
    ResearchOnly(String),
}

/// Construct a placeholder public key (research only).
pub fn placeholder_public_key(params: ParameterSet) -> ThresholdPublicKey {
    ThresholdPublicKey {
        params,
        bytes: vec![0u8; params.public_key_size()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_set_sizes() {
        assert_eq!(ParameterSet::MlKem512.public_key_size(), 800);
        assert_eq!(ParameterSet::MlKem768.public_key_size(), 1184);
        assert_eq!(ParameterSet::MlKem1024.public_key_size(), 1568);
    }

    #[test]
    fn shared_secret_always_32() {
        for params in [ParameterSet::MlKem512, ParameterSet::MlKem768, ParameterSet::MlKem1024] {
            assert_eq!(params.shared_secret_size(), 32);
        }
    }
}
