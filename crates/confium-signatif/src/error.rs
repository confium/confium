//! Errors for the SIGNATIF framework implementation.

use thiserror::Error;

/// Errors produced by the SIGNATIF framework implementation.
#[derive(Debug, Error)]
pub enum SignatifError {
    /// A verification path could not be found from an artifact signer to
    /// any root anchor in the trust anchor bundle.
    #[error("no verification path to a trusted root")]
    NoPath,
    /// Scope widening detected at a delegation link — a hard failure.
    #[error("scope widening at delegation link {parent} -> {child} on dimension {dimension}")]
    ScopeWidening {
        /// Parent authority identifier.
        parent: String,
        /// Child authority identifier.
        child: String,
        /// The scope dimension that was widened.
        dimension: String,
    },
    /// A signature failed to verify.
    #[error("signature verification failed for {context}")]
    BadSignature {
        /// What was being verified when the failure occurred.
        context: String,
    },
    /// The trust anchor bundle is expired or not yet valid.
    #[error("anchor bundle not valid at the evaluation time")]
    BundleValidity,
    /// Artifact format error (version, self-description, replay).
    #[error("artifact format error: {0}")]
    ArtifactFormat(String),
    /// Hard-check failure carrying the failing check name.
    #[error("hard check failed: {0}")]
    HardCheck(String),
    /// A required registry entry is unknown or retired.
    #[error("registry {registry} has no usable entry {entry}")]
    Registry {
        /// Registry name.
        registry: String,
        /// Entry identifier.
        entry: String,
    },
    /// CRL or revocation state error.
    #[error("revocation error: {0}")]
    Revocation(String),
    /// Ceremony transcript audit failure.
    #[error("ceremony audit failure: {0}")]
    Ceremony(String),
    /// Serialization or canonicalization failure.
    #[error("encoding error: {0}")]
    Encoding(String),
}

/// Convenient result alias.
pub type SignatifResult<T> = Result<T, SignatifError>;
