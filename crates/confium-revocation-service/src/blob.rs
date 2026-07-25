//! Revocation blob (user-side prepared, service-side decrypted).
//!
//! Mirrors Thunderbird's blob structure but uses threshold KEM
//! encryption to recipient quorum instead of single-party encryption.

use serde::{Deserialize, Serialize};

/// A revocation blob prepared by the user's client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationBlob {
    /// Email associated with the key (for verification flow).
    pub user_email: String,
    /// Fingerprint of the key being revoked.
    pub key_fingerprint: String,
    /// Threshold KEM encapsulated key (encrypted to service quorum's public key).
    pub encapsulated_key: Vec<u8>,
    /// AEAD ciphertext of (revocation_signature + public_key).
    pub ciphertext: Vec<u8>,
    /// AEAD nonce.
    pub nonce: Vec<u8>,
}

/// Errors during revocation blob operations.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    /// Blob malformed.
    #[error("malformed blob: {0}")]
    Malformed(String),
    /// Verification token invalid.
    #[error("verification token invalid: {0}")]
    InvalidToken(String),
    /// Email verification failed.
    #[error("email verification failed: {0}")]
    EmailVerificationFailed(String),
    /// Submission already in progress.
    #[error("submission already in progress for {0}")]
    AlreadyInProgress(String),
    /// Threshold decryption failed.
    #[error("threshold decryption failed: {0}")]
    ThresholdDecryption(String),
    /// Keyserver publication failed.
    #[error("keyserver publication failed: {0}")]
    Publish(String),
}
