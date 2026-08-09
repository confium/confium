//! RFC 4998 Evidence Record Syntax (ERS) for long-term archival.
//!
//! Implements Evidence Records that protect artifacts over decades
//! as hash algorithms weaken. Periodic re-timestamping with stronger
//! algorithms maintains verifiability.
//!
//! Confium extends standard ERS with periodic re-quorum: every N years,
//! the current quorum re-signs and re-encrypts archives under current
//! algorithm suites.
//!
//! See `TODO.roadmap/37-long-term-archival.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Hash algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA3-256.
    Sha3_256,
}

/// An Evidence Record (RFC 4998).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// ERS version.
    pub version: u32,
    /// Digest algorithms used (one per ArchiveTimeStampSequence entry).
    pub digest_algorithms: Vec<HashAlgorithm>,
    /// Sequence of archive timestamps (added as algorithms age).
    pub archive_time_stamp_sequences: Vec<ArchiveTimeStampSequence>,
}

/// A sequence of archive timestamps covering a time period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveTimeStampSequence {
    /// Sequence number (0-based).
    pub sequence_number: u32,
    /// Reduced hash tree (Merkle tree of artifact hashes).
    pub reduced_hash_tree: Vec<[u8; 32]>,
    /// The RFC 3161 timestamp token.
    pub time_stamp: TimeStamp,
    /// When the timestamp was applied.
    pub applied_at: DateTime<Utc>,
}

/// An RFC 3161 timestamp token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStamp {
    /// TSA (Time Stamping Authority) identifier.
    pub tsa_id: String,
    /// Timestamp token bytes (PKCS#7 SignedData from TSA).
    pub token: Vec<u8>,
    /// Hash that was timestamped.
    pub hashed_message: [u8; 32],
}

/// Errors during ERS operations.
#[derive(Debug, thiserror::Error)]
pub enum ErsError {
    /// Hash algorithm mismatch.
    #[error("hash algorithm mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch {
        /// Expected.
        expected: HashAlgorithm,
        /// Actual.
        actual: HashAlgorithm,
    },
    /// TSA not trusted.
    #[error("TSA not trusted: {0}")]
    UntrustedTsa(String),
    /// Hash chain broken.
    #[error("hash chain broken at sequence {0}")]
    BrokenChain(u32),
}

/// Build an initial Evidence Record for an artifact.
pub fn build_initial_evidence_record(
    artifact_hash: [u8; 32],
    algorithm: HashAlgorithm,
    tsa_id: impl Into<String>,
    timestamp_token: Vec<u8>,
) -> EvidenceRecord {
    let ts = TimeStamp {
        tsa_id: tsa_id.into(),
        token: timestamp_token,
        hashed_message: artifact_hash,
    };
    let seq = ArchiveTimeStampSequence {
        sequence_number: 0,
        reduced_hash_tree: vec![artifact_hash],
        time_stamp: ts,
        applied_at: Utc::now(),
    };
    EvidenceRecord {
        version: 1,
        digest_algorithms: vec![algorithm],
        archive_time_stamp_sequences: vec![seq],
    }
}

/// Renew an existing Evidence Record by adding a new timestamp sequence
/// with a stronger hash algorithm.
pub fn renew_evidence_record(
    existing: &mut EvidenceRecord,
    new_algorithm: HashAlgorithm,
    new_artifact_hash: [u8; 32],
    tsa_id: impl Into<String>,
    timestamp_token: Vec<u8>,
) {
    let next_seq = existing.archive_time_stamp_sequences.len() as u32;
    let ts = TimeStamp {
        tsa_id: tsa_id.into(),
        token: timestamp_token,
        hashed_message: new_artifact_hash,
    };
    let seq = ArchiveTimeStampSequence {
        sequence_number: next_seq,
        reduced_hash_tree: vec![new_artifact_hash],
        time_stamp: ts,
        applied_at: Utc::now(),
    };
    existing.digest_algorithms.push(new_algorithm);
    existing.archive_time_stamp_sequences.push(seq);
}

/// Count renewal rounds applied so far.
pub fn renewal_count(record: &EvidenceRecord) -> u32 {
    record.archive_time_stamp_sequences.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_initial_record() {
        let r = build_initial_evidence_record(
            [1u8; 32],
            HashAlgorithm::Sha256,
            "tsa.example.com",
            vec![0u8; 100],
        );
        assert_eq!(renewal_count(&r), 1);
        assert_eq!(r.digest_algorithms, vec![HashAlgorithm::Sha256]);
    }

    #[test]
    fn renew_adds_sequence() {
        let mut r = build_initial_evidence_record([1u8; 32], HashAlgorithm::Sha256, "tsa", vec![]);
        renew_evidence_record(&mut r, HashAlgorithm::Sha384, [2u8; 32], "tsa2", vec![]);
        assert_eq!(renewal_count(&r), 2);
        assert_eq!(r.digest_algorithms.len(), 2);
    }
}
