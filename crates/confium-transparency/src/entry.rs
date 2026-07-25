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
    pub fn new(
        sequence: u64,
        artifact_type: ArtifactType,
        artifact_hash: [u8; 32],
    ) -> Self {
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
}
