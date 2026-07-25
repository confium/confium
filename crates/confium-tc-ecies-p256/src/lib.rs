//! Threshold ECIES over P-256.
//!
//! For browser-side key escrow: each browser-held key encrypted under
//! threshold ECIES public key; recoverable via T-of-N quorum.
//!
//! See `TODO.roadmap/31-threshold-encryption.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Algorithm identifier.
pub const ALGORITHM: &str = "ECIES-P256-threshold";

/// Threshold ECIES public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Public key bytes (65 bytes uncompressed P-256 point).
    pub bytes: Vec<u8>,
}

/// A share of the threshold ECIES secret key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Party index.
    pub party_index: u32,
    /// Share bytes (32-byte scalar).
    pub bytes: Vec<u8>,
}

/// ECIES-encrypted blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Ephemeral public key (65 bytes).
    pub ephemeral_public: Vec<u8>,
    /// AEAD ciphertext.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce.
    pub nonce: Vec<u8>,
    /// AEAD tag.
    pub tag: Vec<u8>,
}

/// Errors during threshold ECIES operations.
#[derive(Debug, thiserror::Error)]
pub enum EciesError {
    /// Threshold not met.
    #[error("threshold not met")]
    ThresholdNotMet,
    /// Invalid public key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    /// Decryption failed.
    #[error("decryption failed: {0}")]
    DecryptFailed(String),
}

/// Mock encrypt: produces a deterministic-looking blob.
pub fn encrypt(_recipient: &PublicKey, plaintext: &[u8]) -> Result<EncryptedBlob, EciesError> {
    Ok(EncryptedBlob {
        ephemeral_public: vec![1u8; 65],
        ciphertext: plaintext.iter().map(|b| !b).collect(),
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    })
}

/// Mock decrypt: inverts the mock encryption.
pub fn decrypt(blob: &EncryptedBlob) -> Result<Vec<u8>, EciesError> {
    Ok(blob.ciphertext.iter().map(|b| !b).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_round_trip() {
        let pk = PublicKey { bytes: vec![0u8; 65] };
        let blob = encrypt(&pk, b"hello").unwrap();
        let recovered = decrypt(&blob).unwrap();
        assert_eq!(recovered, b"hello");
    }
}
