//! Transparency log entries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Type of artifact recorded in the transparency log.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    /// Certificate issuance.
    CertificateIssuance,
    /// Certificate revocation.
    CertificateRevocation,
    /// Threshold signature produced.
    ThresholdSignature,
    /// Threshold encryption produced.
    ThresholdEncryption,
    /// Quorum committee re-shared.
    DirectorRotation,
    /// Quorum policy changed (T, N, predicates).
    QuorumPolicy,
    /// Director identity added/removed.
    DirectorIdentity,
    /// Archive renewal (re-quorum of long-term archival).
    ArchiveRenewal,
}

impl ArtifactType {
    /// Stable string identifier (snake_case). Round-trips with
    /// [`ArtifactType::from_str`]. Used by every language binding so
    /// there's a single source of truth for the variant names.
    pub const fn as_str(self) -> &'static str {
        match self {
            ArtifactType::CertificateIssuance => "certificate_issuance",
            ArtifactType::CertificateRevocation => "certificate_revocation",
            ArtifactType::ThresholdSignature => "threshold_signature",
            ArtifactType::ThresholdEncryption => "threshold_encryption",
            ArtifactType::DirectorRotation => "director_rotation",
            ArtifactType::QuorumPolicy => "quorum_policy",
            ArtifactType::DirectorIdentity => "director_identity",
            ArtifactType::ArchiveRenewal => "archive_renewal",
        }
    }

    /// All variants in declaration order — useful for binding iterators
    /// and CLI argument completion.
    pub const ALL: &[ArtifactType] = &[
        ArtifactType::CertificateIssuance,
        ArtifactType::CertificateRevocation,
        ArtifactType::ThresholdSignature,
        ArtifactType::ThresholdEncryption,
        ArtifactType::DirectorRotation,
        ArtifactType::QuorumPolicy,
        ArtifactType::DirectorIdentity,
        ArtifactType::ArchiveRenewal,
    ];
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ArtifactType {
    type Err = UnknownArtifactType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for variant in ArtifactType::ALL {
            if variant.as_str() == s {
                return Ok(*variant);
            }
        }
        Err(UnknownArtifactType {
            input: s.to_string(),
        })
    }
}

/// Error returned by [`ArtifactType::from_str`] when the input doesn't
/// match any known variant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown artifact_type '{input}' (expected one of: {})", ArtifactType::ALL.iter().map(|v| v.as_str()).collect::<Vec<_>>().join(", "))]
pub struct UnknownArtifactType {
    input: String,
}

/// A single entry in the transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// When the entry was appended.
    pub timestamp: DateTime<Utc>,
    /// Type of artifact.
    pub artifact_type: ArtifactType,
    /// SHA-256 hash of the artifact being recorded.
    pub artifact_hash: [u8; 32],
    /// Optional deployment-specific metadata (JSON).
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl MerkleEntry {
    /// Construct a new entry with the current timestamp.
    pub fn new(sequence: u64, artifact_type: ArtifactType, artifact_hash: [u8; 32]) -> Self {
        Self {
            sequence,
            timestamp: Utc::now(),
            artifact_type,
            artifact_hash,
            metadata: serde_json::Value::Null,
        }
    }

    /// Compute the SHA-256 hash of this entry's contents (sequence + timestamp + artifact_hash).
    pub fn entry_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.sequence.to_le_bytes());
        // Encode timestamp as a fixed-size byte sequence
        let ts_micros = self.timestamp.timestamp_micros();
        hasher.update(ts_micros.to_le_bytes());
        hasher.update(self.artifact_hash);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_hash_is_deterministic() {
        let e1 = MerkleEntry::new(1, ArtifactType::CertificateIssuance, [0u8; 32]);
        let e2 = MerkleEntry::new(1, ArtifactType::CertificateIssuance, [0u8; 32]);
        // Same content, but timestamp differs — hash will differ. Test that.
        // For deterministic hash test, set timestamp explicitly:
        let now = Utc::now();
        let mut a = e1;
        let mut b = e2;
        a.timestamp = now;
        b.timestamp = now;
        assert_eq!(a.entry_hash(), b.entry_hash());
    }

    #[test]
    fn different_entries_different_hashes() {
        let now = Utc::now();
        let mut e1 = MerkleEntry::new(1, ArtifactType::CertificateIssuance, [0u8; 32]);
        let mut e2 = MerkleEntry::new(2, ArtifactType::CertificateIssuance, [0u8; 32]);
        e1.timestamp = now;
        e2.timestamp = now;
        assert_ne!(e1.entry_hash(), e2.entry_hash());
    }

    #[test]
    fn artifact_type_as_str_roundtrips() {
        use std::str::FromStr;
        for variant in ArtifactType::ALL {
            let s = variant.as_str();
            let parsed = ArtifactType::from_str(s).unwrap();
            assert_eq!(parsed, *variant);
        }
    }

    #[test]
    fn artifact_type_display_matches_as_str() {
        for variant in ArtifactType::ALL {
            assert_eq!(variant.to_string(), variant.as_str());
        }
    }

    #[test]
    fn artifact_type_unknown_string_fails() {
        use std::str::FromStr;
        let result = ArtifactType::from_str("not_a_real_type");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not_a_real_type"));
        assert!(err.to_string().contains("certificate_issuance"));
    }
}
