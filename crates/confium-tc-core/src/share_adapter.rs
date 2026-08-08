//! Cross-scheme share adapter — normalized intermediate representation.
//!
//! Different threshold schemes (CMP20, FROST-P256, GG18) use different
//! share types internally. The `NormalizedShare` struct provides a
//! scheme-agnostic format for serialization, migration, and interop.
//!
//! Each scheme crate implements `ShareAdapter` for its own share type,
//! converting to/from `NormalizedShare`.

use serde::{Deserialize, Serialize};

/// Scheme-agnostic share representation. Any P-256-based threshold
/// scheme share can be normalized to this format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedShare {
    /// Source scheme (e.g., "CMP20", "FROST-P256", "GG18").
    pub scheme: String,
    /// Quorum identifier.
    pub quorum_id: String,
    /// 1-based party index.
    pub party_idx: u32,
    /// Threshold T.
    pub threshold: u32,
    /// Total party count N.
    pub party_count: u32,
    /// Share scalar (32 bytes, big-endian).
    pub scalar_hex: String,
    /// Joint public key (SEC1 uncompressed, hex).
    pub public_key_hex: String,
}

/// Errors during share normalization.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// Invalid scalar bytes.
    #[error("invalid scalar: {0}")]
    InvalidScalar(String),
    /// Invalid public key bytes.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    /// Field mismatch.
    #[error("field mismatch: {0}")]
    FieldMismatch(String),
}

impl NormalizedShare {
    /// Create a new normalized share.
    pub fn new(
        scheme: &str,
        quorum_id: &str,
        party_idx: u32,
        threshold: u32,
        party_count: u32,
        scalar_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<Self, AdapterError> {
        if scalar_bytes.len() != 32 {
            return Err(AdapterError::InvalidScalar(format!(
                "expected 32 bytes, got {}",
                scalar_bytes.len()
            )));
        }
        Ok(Self {
            scheme: scheme.into(),
            quorum_id: quorum_id.into(),
            party_idx,
            threshold,
            party_count,
            scalar_hex: hex::encode(scalar_bytes),
            public_key_hex: hex::encode(public_key_bytes),
        })
    }

    /// Get the share scalar as bytes.
    pub fn scalar_bytes(&self) -> Result<Vec<u8>, AdapterError> {
        hex::decode(&self.scalar_hex).map_err(|e| AdapterError::InvalidScalar(e.to_string()))
    }

    /// Get the public key as bytes.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, AdapterError> {
        hex::decode(&self.public_key_hex).map_err(|e| AdapterError::InvalidPublicKey(e.to_string()))
    }

    /// Check if two shares are from the same quorum and have the same
    /// joint public key (i.e., they're compatible for aggregation).
    pub fn is_compatible_with(&self, other: &NormalizedShare) -> bool {
        self.quorum_id == other.quorum_id
            && self.public_key_hex == other.public_key_hex
            && self.threshold == other.threshold
            && self.party_count == other.party_count
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Rename the scheme. Used when migrating a share from one scheme
    /// to another (e.g., "CMP20" → "FROST-P256" after re-sharing).
    pub fn reclassify(mut self, new_scheme: &str) -> Self {
        self.scheme = new_scheme.into();
        self
    }
}

/// Trait for converting scheme-specific share types to/from the
/// normalized representation.
pub trait ShareAdapter {
    /// Convert to a normalized share.
    fn to_normalized(&self, quorum_id: &str) -> Result<NormalizedShare, AdapterError>;

    /// Convert from a normalized share. Returns `Err` if the scheme
    /// doesn't match.
    fn from_normalized(normalized: &NormalizedShare) -> Result<Self, AdapterError>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_share(scheme: &str) -> NormalizedShare {
        NormalizedShare::new(scheme, "quorum-alpha", 3, 2, 5, &[0xAA; 32], &[0x04; 65]).unwrap()
    }

    #[test]
    fn new_validates_scalar_length() {
        assert!(NormalizedShare::new("CMP20", "q", 1, 2, 3, &[0; 31], &[0; 65]).is_err());
        assert!(NormalizedShare::new("CMP20", "q", 1, 2, 3, &[0; 32], &[0; 65]).is_ok());
    }

    #[test]
    fn scalar_bytes_round_trips() {
        let share = make_share("CMP20");
        let bytes = share.scalar_bytes().unwrap();
        assert_eq!(bytes, vec![0xAA; 32]);
    }

    #[test]
    fn public_key_bytes_round_trips() {
        let share = make_share("CMP20");
        let bytes = share.public_key_bytes().unwrap();
        assert_eq!(bytes, vec![0x04; 65]);
    }

    #[test]
    fn is_compatible_same_quorum() {
        let a = make_share("CMP20");
        let b = make_share("CMP20");
        assert!(a.is_compatible_with(&b));
    }

    #[test]
    fn is_incompatible_different_quorum() {
        let a = make_share("CMP20");
        let mut b = make_share("CMP20");
        b.quorum_id = "different".into();
        assert!(!a.is_compatible_with(&b));
    }

    #[test]
    fn is_incompatible_different_threshold() {
        let a = make_share("CMP20");
        let mut b = make_share("CMP20");
        b.threshold = 3;
        assert!(!a.is_compatible_with(&b));
    }

    #[test]
    fn json_round_trip() {
        let share = make_share("CMP20");
        let json = share.to_json().unwrap();
        let recovered = NormalizedShare::from_json(&json).unwrap();
        assert_eq!(share, recovered);
    }

    #[test]
    fn reclassify_changes_scheme() {
        let share = make_share("CMP20");
        let reclassified = share.reclassify("FROST-P256");
        assert_eq!(reclassified.scheme, "FROST-P256");
    }

    #[test]
    fn reclassify_preserves_other_fields() {
        let share = make_share("CMP20");
        let reclassified = share.reclassify("GG18");
        assert_eq!(reclassified.quorum_id, "quorum-alpha");
        assert_eq!(reclassified.party_idx, 3);
        assert_eq!(reclassified.threshold, 2);
    }
}
