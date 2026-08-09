//! OpenSSL 3.0 provider using Confium for signing.
//!
//! Allows OpenSSL applications (nginx, Apache, OpenSSH, etc.) to use
//! Confium-backed threshold signing keys without code changes.
//! Implements the OpenSSL 3.0 provider API (OSSL_OP_*).
//!
//! The provider is loaded via OpenSSL config or `OPENSSL_CONF` env var:
//! ```text
//! openssl_conf = openssl_init
//!
//! [openssl_init]
//! providers = provider_sect
//!
//! [provider_sect]
//! confium = confium_sect
//!
//! [confium_sect]
//! activate = 1
//! module = /usr/lib/confium/confium_openssl_provider.so
//! ```
//!
//! See `TODO.roadmap/28-mode2-pki-replacement.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

use serde::{Deserialize, Serialize};

/// Provider metadata reported to OpenSSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Provider name (e.g., "confium").
    pub name: String,
    /// Provider version.
    pub version: String,
    /// Provider description.
    pub description: String,
    /// Build info.
    pub buildinfo: String,
}

impl ProviderInfo {
    /// Default Confium provider info.
    pub fn default_confium() -> Self {
        Self {
            name: "confium".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            description: "Confium threshold cryptography provider for OpenSSL 3.0".into(),
            buildinfo: "Confium OpenSSL Provider".into(),
        }
    }
}

/// Operations supported by this provider (subset of OpenSSL OSSL_OP_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Signature production.
    Signer,
    /// Signature verification.
    Verifier,
    /// Digest computation.
    Digester,
    /// Key generation.
    KeyGenerator,
    /// Key import/export.
    KeyEncoder,
    /// Key store.
    StoreLoader,
}

impl Operation {
    /// All operations supported by the Confium provider.
    pub fn all() -> &'static [Operation] {
        &[
            Operation::Signer,
            Operation::Verifier,
            Operation::Digester,
            Operation::KeyGenerator,
            Operation::KeyEncoder,
            Operation::StoreLoader,
        ]
    }
}

/// Algorithms supported (mapped to OpenSSL algorithm names).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    /// Ed25519 over Ed25519 curve.
    Ed25519,
    /// ECDSA over P-256.
    EcdsaP256,
    /// ECDSA over P-384.
    EcdsaP384,
    /// ML-DSA-65 (post-quantum).
    MlDsa65,
    /// Composite Ed25519 + ML-DSA-65.
    CompositeEd25519MlDsa65,
}

impl Algorithm {
    /// OpenSSL algorithm name for this algorithm.
    pub fn openssl_name(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::EcdsaP256 => "ECDSA",
            Algorithm::EcdsaP384 => "ECDSA",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::CompositeEd25519MlDsa65 => "composite-MLDSA65-Ed25519",
        }
    }
}

/// Provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Path to the Confium daemon socket.
    pub daemon_socket: String,
    /// Quorum to use by default.
    pub default_quorum: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_provider_info() {
        let info = ProviderInfo::default_confium();
        assert_eq!(info.name, "confium");
    }

    #[test]
    fn all_operations_non_empty() {
        assert!(!Operation::all().is_empty());
    }

    #[test]
    fn ed25519_openssl_name() {
        assert_eq!(Algorithm::Ed25519.openssl_name(), "Ed25519");
    }
}
