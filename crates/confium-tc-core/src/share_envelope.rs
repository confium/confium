//! Versioned share envelope — canonical wire format for threshold shares.
//!
//! Provides:
//! - Version field for forward/backward compatibility
//! - Scheme identifier (CMP20, FROST-P256, FROST-ed25519, GG18)
//! - Quorum association
//! - Tamper detection via HMAC-SHA256 integrity tag
//!
//! The envelope wraps scheme-specific share bytes without interpreting
//! them. Each scheme (CMP20, FROST, etc.) serializes its own share type
//! to bytes, then the envelope adds the versioning and integrity layer.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// A versioned, integrity-protected threshold share envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareEnvelope {
    /// Envelope format version (currently 1).
    pub version: u8,
    /// Threshold scheme (e.g., "CMP20", "FROST-P256", "GG18").
    pub scheme: String,
    /// Quorum identifier this share belongs to.
    pub quorum_id: String,
    /// Party index (1-based, per DKG convention).
    pub party_idx: u32,
    /// Threshold T.
    pub threshold: u32,
    /// Total party count N.
    pub party_count: u32,
    /// Scheme-specific share bytes (opaque to the envelope).
    pub share_data: Vec<u8>,
    /// HMAC-SHA256 of all the above fields (keyed with the master key).
    #[serde(default)]
    pub integrity_tag: [u8; 32],
}

/// Errors during envelope operations.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// Version mismatch.
    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u8),
    /// Integrity check failed.
    #[error("integrity check failed")]
    IntegrityFailed,
    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Create a new share envelope wrapping scheme-specific share bytes.
/// The integrity tag is computed as HMAC-SHA256 over the envelope
/// fields using `integrity_key` as the HMAC key.
impl ShareEnvelope {
    /// Wrap scheme-specific share bytes into a versioned envelope.
    pub fn wrap(
        scheme: &str,
        quorum_id: &str,
        party_idx: u32,
        threshold: u32,
        party_count: u32,
        share_data: Vec<u8>,
        integrity_key: &[u8],
    ) -> Result<Self, EnvelopeError> {
        let mut envelope = Self {
            version: ENVELOPE_VERSION,
            scheme: scheme.to_string(),
            quorum_id: quorum_id.to_string(),
            party_idx,
            threshold,
            party_count,
            share_data,
            integrity_tag: [0u8; 32],
        };
        envelope.integrity_tag = envelope.compute_tag(integrity_key)?;
        Ok(envelope)
    }

    /// Verify the integrity tag matches the envelope contents.
    /// Uses constant-time comparison to prevent timing side-channels.
    pub fn verify(&self, integrity_key: &[u8]) -> Result<(), EnvelopeError> {
        if self.version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.version));
        }
        let expected = self.compute_tag(integrity_key)?;
        if self.integrity_tag.ct_eq(&expected).into() {
            Ok(())
        } else {
            Err(EnvelopeError::IntegrityFailed)
        }
    }

    /// Extract the share data (after verifying integrity).
    pub fn unwrap(&self, integrity_key: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        self.verify(integrity_key)?;
        Ok(self.share_data.clone())
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        serde_json::to_vec(self).map_err(|e| EnvelopeError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EnvelopeError> {
        serde_json::from_slice(data).map_err(|e| EnvelopeError::Serialization(e.to_string()))
    }

    fn compute_tag(&self, key: &[u8]) -> Result<[u8; 32], EnvelopeError> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| EnvelopeError::Serialization(e.to_string()))?;
        mac.update(&[self.version]);
        mac.update(self.scheme.as_bytes());
        mac.update(self.quorum_id.as_bytes());
        mac.update(&self.party_idx.to_be_bytes());
        mac.update(&self.threshold.to_be_bytes());
        mac.update(&self.party_count.to_be_bytes());
        mac.update(&self.share_data);
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result);
        Ok(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_wrap_unwrap() {
        let key = b"test-integrity-key-12345678901234";
        let share = vec![0xAA; 32];
        let envelope =
            ShareEnvelope::wrap("CMP20", "quorum-alpha", 3, 2, 5, share.clone(), key).unwrap();

        let recovered = envelope.unwrap(key).unwrap();
        assert_eq!(recovered, share);
    }

    #[test]
    fn tampered_share_data_detected() {
        let key = b"test-integrity-key-12345678901234";
        let mut envelope =
            ShareEnvelope::wrap("FROST-P256", "quorum-beta", 1, 3, 5, vec![0x11; 32], key).unwrap();

        envelope.share_data[0] ^= 0xFF;
        assert!(matches!(
            envelope.verify(key),
            Err(EnvelopeError::IntegrityFailed)
        ));
    }

    #[test]
    fn tampered_threshold_detected() {
        let key = b"test-integrity-key-12345678901234";
        let mut envelope =
            ShareEnvelope::wrap("CMP20", "quorum-gamma", 2, 3, 5, vec![0x22; 32], key).unwrap();

        envelope.threshold = 2;
        assert!(matches!(
            envelope.verify(key),
            Err(EnvelopeError::IntegrityFailed)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let key = b"correct-integrity-key-12345678901";
        let wrong_key = b"wrong-integrity-key-123456789012";
        let envelope =
            ShareEnvelope::wrap("GG18", "quorum-delta", 1, 2, 3, vec![0x33; 32], key).unwrap();

        assert!(envelope.verify(wrong_key).is_err());
        assert!(envelope.verify(key).is_ok());
    }

    #[test]
    fn json_serialization_round_trip() {
        let key = b"json-test-key-123456789012345678";
        let envelope =
            ShareEnvelope::wrap("CMP20", "quorum-json", 5, 3, 7, vec![0x44; 32], key).unwrap();

        let json = envelope.to_bytes().unwrap();
        let recovered = ShareEnvelope::from_bytes(&json).unwrap();
        assert_eq!(recovered.version, envelope.version);
        assert_eq!(recovered.scheme, envelope.scheme);
        assert_eq!(recovered.quorum_id, envelope.quorum_id);
        assert_eq!(recovered.party_idx, envelope.party_idx);
        assert_eq!(recovered.threshold, envelope.threshold);
        assert_eq!(recovered.party_count, envelope.party_count);
        assert_eq!(recovered.share_data, envelope.share_data);
        assert_eq!(recovered.integrity_tag, envelope.integrity_tag);

        assert!(recovered.verify(key).is_ok());
    }

    #[test]
    fn version_mismatch_rejected() {
        let key = b"version-test-key-12345678901234";
        let mut envelope =
            ShareEnvelope::wrap("CMP20", "quorum-version", 1, 2, 3, vec![0x55; 32], key).unwrap();
        envelope.version = 99;
        assert!(matches!(
            envelope.verify(key),
            Err(EnvelopeError::UnsupportedVersion(99))
        ));
    }
}
