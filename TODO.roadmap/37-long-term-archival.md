# 37 — Long-term archival (RFC 4998 Evidence Record Syntax)

## Purpose

Artifacts signed in 2026 must verify in 2046. Hash algorithms
weaken over time. RFC 4998 ERS (Evidence Record Syntax) provides
periodic re-timestamping as algorithms age.

For OIML: instruments last 10-20 years. Calibration data and test
reports retained for instrument lifetime. Decades-long archival
required.

## ERS overview

RFC 4998 defines an Evidence Record — a chain of timestamps
protecting an artifact over time. As hash algorithms weaken, new
timestamps are added using stronger algorithms.

```
Artifact (2026)
   │ timestamped with SHA-256 (2026)
   │ timestamped with SHA-384 (2031, after SHA-256 weakens)
   │ timestamped with SHA-512 (2036, after SHA-384 weakens)
   │ ... etc
   ▼
Evidence Record proves artifact existed at each timestamp
```

## Confium extension: periodic re-quorum

Standard ERS only re-timestamps. Confium extends:

Every N years, the **current** deployment quorum:
1. Re-signs the artifact under **current** algorithm suite
   (signature renewal)
2. Re-encrypts archived data under **current** threshold KEM
   (encryption renewal)
3. Adds new Evidence Record entry

The artifact's trust chain evolves with the institution. "Living
will" cryptography.

## Architecture

```rust
pub struct EvidenceRecord {
    pub version: u32,
    pub digest_algorithms: Vec<HashAlgorithm>,
    pub crypto_objects: Vec<CryptoObject>,
    pub archive_time_stamp_sequences: Vec<ArchiveTimeStampSequence>,
}

pub struct ArchiveTimeStampSequence {
    pub sequence_number: u32,
    pub hash_tree: ReducedHashTree,
    pub time_stamp: TimeStamp,           // RFC 3161
    pub attributes: ArchiveTimestampAttributes,
}

pub fn build_initial_evidence_record(
    artifact_hash: [u8; 32],
    initial_algorithm: HashAlgorithm,
) -> Result<EvidenceRecord>;

pub fn renew_evidence_record(
    existing: &EvidenceRecord,
    new_algorithm: HashAlgorithm,
    threshold_quorum: &Quorum,
) -> Result<EvidenceRecord>;

pub fn verify_evidence_record(
    record: &EvidenceRecord,
    artifact: &[u8],
    trusted_tsas: &[Tsa>,
) -> Result<VerificationResult>;
```

## Re-encryption extension

For threshold-encrypted archives (test reports, calibration data):

```rust
pub fn renew_threshold_encryption(
    encrypted_archive: &ThresholdEncryptedBlob,
    old_quorum_pubkey: &PublicKey,
    new_quorum_pubkey: &PublicKey,
    threshold_quorum: &Quorum,
) -> Result<ThresholdEncryptedBlob>;
```

Old quorum threshold-decrypts; new quorum threshold-encrypts. No
plaintext exposure beyond the brief renewal window.

## Ceremony

Every 5 years (configurable):

1. Coordinator schedules renewal
2. Current quorum members participate async (like signing session)
3. Each artifact re-signed under current algorithm
4. Each encrypted archive re-encrypted under current KEM
5. New Evidence Record entries added
6. Transparency log records all renewals
7. OTS-anchored

## Schedule for OIML/CNML

- 2026: Initial signatures (Ed25519 + ML-DSA-65 composite)
- 2031: Re-quorum. Composite adds third algorithm if available.
- 2036: Re-quorum. Migration to next-gen PQ if ML-DSA weakens.
- 2041: Re-quorum.
- ...

Each re-quorum is itself an event in the transparency log, signed
by the then-current BIML quorum.

## Crate scope

### `confium-ers` (P1)

- RFC 4998 Evidence Record implementation
- RFC 3161 timestamp client
- Re-quorum ceremony orchestration
- Re-encryption coordination (uses `confium-tc-kem`)
- Storage: Evidence Records stored alongside artifacts

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/31-threshold-encryption.md` — re-encryption
- `TODO.roadmap/36-transparency-and-ots.md` — re-quorum events logged
- [RFC 4998 Evidence Record Syntax](https://www.rfc-editor.org/rfc/rfc4998)
- [RFC 3161 Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161)
