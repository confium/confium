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
use sha2::{Digest, Sha256};

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
    /// The record uses an algorithm the verifier can't hash with.
    ///
    /// The evidence-record data model stores fixed 32-byte digests,
    /// which fits SHA-256 but not SHA-384 (48 bytes) or SHA-512
    /// (64 bytes). Supporting those requires widening the hash
    /// fields to `Vec<u8>` — tracked as a follow-up. Verification
    /// refuses rather than truncating a stronger digest, which would
    /// weaken it.
    #[error("algorithm {0:?} not supported by the verifier's 32-byte digest model")]
    UnsupportedAlgorithm(HashAlgorithm),
}

/// A trusted Time Stamping Authority identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tsa {
    /// TSA identifier (must match `TimeStamp::tsa_id`).
    pub id: String,
}

/// Per-sequence outcome of [`verify_evidence_record`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceCheck {
    /// Sequence number this check covers.
    pub sequence_number: u32,
    /// Whether the digest, TSA, and ordering checks all passed.
    pub verified: bool,
    /// First failure, if any.
    pub error: Option<String>,
}

/// Outcome of [`verify_evidence_record`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErsVerificationResult {
    /// True iff every sequence verified.
    pub valid: bool,
    /// Per-sequence detail, in record order.
    pub sequences: Vec<SequenceCheck>,
}

/// Hash `data` with `algorithm`, returning the 32-byte digest.
fn hash_with(algorithm: &HashAlgorithm, data: &[u8]) -> Result<[u8; 32], ErsError> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let d: [u8; 32] = Sha256::digest(data).into();
            Ok(d)
        }
        other => Err(ErsError::UnsupportedAlgorithm(other.clone())),
    }
}

/// Verify an Evidence Record end-to-end against the artifact it
/// protects and the set of trusted TSAs.
///
/// Checks, per RFC 4998 as realized by this data model:
///
/// 1. `digest_algorithms.len()` matches the sequence count.
/// 2. Every sequence's `hashed_message` equals the digest of
///    `artifact` under that sequence's declared algorithm (each
///    renewal re-hashes the same artifact under a stronger hash).
/// 3. Every `time_stamp.tsa_id` is in `trusted_tsas`.
/// 4. `applied_at` timestamps are non-decreasing across sequences.
///
/// Sequences using algorithms whose digests don't fit the model's
/// 32-byte fields (SHA-384/512, SHA3-256) are reported as
/// unsupported — see [`ErsError::UnsupportedAlgorithm`] — rather
/// than being silently skipped or truncated.
pub fn verify_evidence_record(
    record: &EvidenceRecord,
    artifact: &[u8],
    trusted_tsas: &[Tsa],
) -> Result<ErsVerificationResult, ErsError> {
    let mut sequences = Vec::with_capacity(record.archive_time_stamp_sequences.len());
    let mut all_valid = record.digest_algorithms.len() == record.archive_time_stamp_sequences.len();
    let mut prev_applied_at: Option<DateTime<Utc>> = None;

    for (i, seq) in record.archive_time_stamp_sequences.iter().enumerate() {
        let algorithm = record.digest_algorithms.get(i);
        let mut err = match algorithm {
            None => Some("no digest algorithm declared for this sequence".to_string()),
            Some(alg) => match hash_with(alg, artifact) {
                Ok(digest) if seq.time_stamp.hashed_message == digest => None,
                Ok(_) => Some(format!("artifact digest mismatch under {alg:?}")),
                Err(e) => Some(e.to_string()),
            },
        };

        if err.is_none() && !trusted_tsas.iter().any(|t| t.id == seq.time_stamp.tsa_id) {
            err = Some(format!("untrusted TSA: {}", seq.time_stamp.tsa_id));
        }

        if err.is_none() {
            if let Some(prev) = prev_applied_at {
                if seq.applied_at < prev {
                    err = Some("timestamp went backwards".to_string());
                }
            }
        }

        prev_applied_at = Some(seq.applied_at);
        let verified = err.is_none();
        if !verified {
            all_valid = false;
        }
        sequences.push(SequenceCheck {
            sequence_number: seq.sequence_number,
            verified,
            error: err,
        });
    }

    Ok(ErsVerificationResult {
        valid: all_valid,
        sequences,
    })
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

    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        Sha256::digest(data).into()
    }

    fn trusted(id: &str) -> Vec<Tsa> {
        vec![Tsa { id: id.to_string() }]
    }

    #[test]
    fn verify_accepts_valid_initial_record() {
        let artifact = b"calibration report 2026";
        let digest = sha256(artifact);
        let r = build_initial_evidence_record(digest, HashAlgorithm::Sha256, "tsa", vec![0u8; 100]);
        let res = verify_evidence_record(&r, artifact, &trusted("tsa")).unwrap();
        assert!(res.valid);
        assert_eq!(res.sequences.len(), 1);
        assert!(res.sequences[0].verified);
    }

    #[test]
    fn verify_rejects_wrong_artifact() {
        let digest = sha256(b"real artifact");
        let r = build_initial_evidence_record(digest, HashAlgorithm::Sha256, "tsa", vec![]);
        let res = verify_evidence_record(&r, b"tampered artifact", &trusted("tsa")).unwrap();
        assert!(!res.valid);
        assert!(
            res.sequences[0]
                .error
                .as_deref()
                .unwrap()
                .contains("digest mismatch")
        );
    }

    #[test]
    fn verify_rejects_untrusted_tsa() {
        let artifact = b"artifact";
        let r = build_initial_evidence_record(
            sha256(artifact),
            HashAlgorithm::Sha256,
            "rogue-tsa",
            vec![],
        );
        let res = verify_evidence_record(&r, artifact, &trusted("good-tsa")).unwrap();
        assert!(!res.valid);
        assert!(
            res.sequences[0]
                .error
                .as_deref()
                .unwrap()
                .contains("untrusted TSA")
        );
    }

    #[test]
    fn verify_rejects_backwards_timestamps() {
        let artifact = b"artifact";
        let mut r =
            build_initial_evidence_record(sha256(artifact), HashAlgorithm::Sha256, "tsa", vec![]);
        // Second sequence with an earlier applied_at.
        let earlier = Utc::now() - chrono::Duration::days(365);
        r.archive_time_stamp_sequences
            .push(ArchiveTimeStampSequence {
                sequence_number: 1,
                reduced_hash_tree: vec![sha256(artifact)],
                time_stamp: TimeStamp {
                    tsa_id: "tsa".into(),
                    token: vec![],
                    hashed_message: sha256(artifact),
                },
                applied_at: earlier,
            });
        r.digest_algorithms.push(HashAlgorithm::Sha256);
        let res = verify_evidence_record(&r, artifact, &trusted("tsa")).unwrap();
        assert!(!res.valid);
        assert!(
            res.sequences[1]
                .error
                .as_deref()
                .unwrap()
                .contains("backwards")
        );
    }

    #[test]
    fn verify_rejects_algorithm_count_mismatch() {
        let artifact = b"artifact";
        let mut r =
            build_initial_evidence_record(sha256(artifact), HashAlgorithm::Sha256, "tsa", vec![]);
        r.digest_algorithms.clear();
        let res = verify_evidence_record(&r, artifact, &trusted("tsa")).unwrap();
        assert!(!res.valid);
        assert!(
            res.sequences[0]
                .error
                .as_deref()
                .unwrap()
                .contains("no digest algorithm")
        );
    }

    #[test]
    fn verify_reports_unsupported_algorithm_honestly() {
        let artifact = b"artifact";
        let mut r =
            build_initial_evidence_record(sha256(artifact), HashAlgorithm::Sha256, "tsa", vec![]);
        renew_evidence_record(&mut r, HashAlgorithm::Sha384, [9u8; 32], "tsa", vec![]);
        let res = verify_evidence_record(&r, artifact, &trusted("tsa")).unwrap();
        assert!(!res.valid);
        // First sequence fine, second reports the model limitation.
        assert!(res.sequences[0].verified);
        assert!(
            res.sequences[1]
                .error
                .as_deref()
                .unwrap()
                .contains("not supported")
        );
    }
}
