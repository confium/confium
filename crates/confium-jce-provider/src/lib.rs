//! Java Cryptography Extension (JCE) provider for Confium.
//!
//! Allows Java applications using JCA (Java Cryptography Architecture)
//! and JKS (Java KeyStore) to use Confium-backed threshold signing
//! keys transparently.
//!
//! Real Java integration requires JNI bindings; this crate provides
//! the Rust-side logic that the JNI layer calls into.
//!
//! See `TODO.roadmap/28-mode2-pki-replacement.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// JCE provider info (mirrors `java.security.Provider`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JceProviderInfo {
    /// Provider name (e.g., "Confium").
    pub name: String,
    /// Version string.
    pub version: String,
    /// Provider info string.
    pub info: String,
}

impl JceProviderInfo {
    /// Default Confium JCE provider info.
    pub fn default_confium() -> Self {
        Self {
            name: "Confium".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            info: "Confium threshold cryptography provider for Java".into(),
        }
    }
}

/// Java algorithm names this provider handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaAlgorithm {
    /// Ed25519 signature.
    Ed25519,
    /// ECDSA P-256 signature.
    EcdsaP256,
    /// ML-DSA-65 (post-quantum).
    MlDsa65,
}

impl JavaAlgorithm {
    /// Java standard algorithm name.
    pub fn java_name(&self) -> &'static str {
        match self {
            JavaAlgorithm::Ed25519 => "Ed25519",
            JavaAlgorithm::EcdsaP256 => "SHA256withECDSA",
            JavaAlgorithm::MlDsa65 => "ML-DSA-65",
        }
    }
}

/// Errors during JCE operations.
#[derive(Debug, thiserror::Error)]
pub enum JceError {
    /// Algorithm not supported.
    #[error("algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),
    /// Threshold signing failed.
    #[error("threshold signing failed: {0}")]
    SignFailed(String),
    /// Key not found in store.
    #[error("key not found: {0}")]
    KeyNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_provider_info() {
        let info = JceProviderInfo::default_confium();
        assert_eq!(info.name, "Confium");
    }

    #[test]
    fn java_algorithm_names() {
        assert_eq!(JavaAlgorithm::Ed25519.java_name(), "Ed25519");
        assert_eq!(JavaAlgorithm::EcdsaP256.java_name(), "SHA256withECDSA");
    }
}
