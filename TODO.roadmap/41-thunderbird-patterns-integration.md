# 41 — Thunderbird patterns: revocation service and key backup integration

## Source

Two design proposals by Kai Engert (Thunderbird / Mozilla):

- **Revocation Service** (`tb-misc/revocation-service.md`, March 2026):
  IMAP-based revocation escrow. Encrypted revocation certificate
  stored on user's IMAP; Thunderbird service decrypts after email
  verification + 24-hour delay. Two-party authorization (IMAP +
  Thunderbird) — neither alone can revoke.

- **Key Backup and Recovery Strategy** (`tb-misc/key-backup-recovery-strategy.md`,
  April 2026): 256-bit Recovery Code on paper protects a post-quantum
  recovery keypair. Encrypted backups stored on IMAP, signed with
  device-local signing subkey. Optional Cross-Device Trust Sync.

## Why these matter to Confium

Both proposals describe **threshold-adjacent problems** but solve
them with simpler primitives (single-party encryption + two-party
authorization). Confium's threshold cryptography materially improves
both designs.

### Revocation Service: 2-of-2 → T-of-N

Thunderbird's design: IMAP server holds encrypted blob, Thunderbird
service holds decryption key. Neither alone can revoke.

**Confium improvement**: generalize to **T-of-N threshold authorization**.
The service decryption key is threshold-held across multiple
independent operators (Thunderbird + Mozilla + independent watchdog).
Any T-of-N must collaborate to decrypt a revocation blob. No single
compelled party can revoke.

Concrete:
- Replace `service_decryption_key` (single RSA keypair in HSM) with
  `service_threshold_keypair` (T-of-N FROST or threshold ElGamal).
- Revocation blob encrypted to threshold public key.
- Decryption requires quorum ceremony (async via coordinator).
- Audit log records which T of N participated.

This eliminates the **"compelled revocation"** risk: even a legal
order against Thunderbird cannot revoke a user's key, because
Thunderbird alone cannot perform the decryption.

### Key Backup: paper code → social/institutional threshold

Thunderbird's design: 256-bit paper Recovery Code. Single point of
failure — lose the paper, lose the keys.

**Confium improvement**: replace single paper code with **T-of-N
threshold recovery**. User's recovery keypair encrypted to a
threshold public key held by N custodians. Any T custodians
collaborate to recover.

Custodian options:
- **Social**: T of N trusted friends/family, each holding a share on
  their YubiKey
- **Institutional**: T of N designated institutions (e.g., 2 of:
  user's employer, their lawyer, their bank)
- **Hybrid**: 1 institutional custodian + 2 personal custodians,
  recoverable via 2-of-3

Concrete for Thunderbird:
- Recovery keypair encrypted under `user_threshold_pubkey`
- Encrypted blob stored on IMAP (as in current design)
- Recovery requires T-of-N custodians to participate in async
  threshold decryption ceremony
- Each custodian's share on their YubiKey via PKCS#11 wrapping
- No paper code to lose or photograph

### Will these be useful to Confium users? Yes — across all three modes

| Mode | Use case |
|---|---|
| Mode 1 (peer) | Social key recovery for personal threshold wallets / custody |
| Mode 2 (PKI replacement) | Enterprise employee key escrow to corporate quorum; threshold-backed corporate revocation service |
| Mode 3 (certificate PKI) | OIML CNML lab key escrow to IA quorum; manufacturer key escrow to IA quorum; IA threshold revocation |

## New crates inspired by these patterns

### `confium-patterns` (escrow) (P0)

Threshold key backup / escrow orchestration. Wraps `confium-tc` (kem).

```rust
pub struct EscrowService {
    quorum_public_keys: HashMap<QuorumId, PublicKey>,
    audit_logger: AuditLogger,
}

impl EscrowService {
    /// Encrypt a key (or any secret) to a recipient quorum.
    /// Returns a blob that requires T-of-N threshold decryption to recover.
    pub fn escrow(
        &self,
        plaintext_key: &[u8],
        recipient_quorum: &QuorumId,
    ) -> Result<EscrowBlob>;

    /// Recover a key from an escrow blob.
    /// Requires T-of-N custodians to participate in threshold decryption.
    /// Recovery event audit-logged with all participating custodian identities.
    pub fn recover(
        &self,
        blob: &EscrowBlob,
        threshold_session: &TcKemSession,
    ) -> Result<RecoveredKey>;
}

pub struct EscrowBlob {
    pub recipient_quorum_id: QuorumId,
    pub encapsulated_key: Vec<u8>,    // threshold KEM encapsulated
    pub ciphertext: Vec<u8>,           // AEAD ciphertext of plaintext_key
    pub metadata: EscrowMetadata,
}

pub struct EscrowMetadata {
    pub escrowed_at: DateTime<Utc>,
    pub escrowed_by: String,
    pub key_id: String,
    pub key_type: KeyType,
    pub custodian_count: u32,
    pub threshold: u32,
}
```

### `confium-patterns` (revocation) (P1)

Threshold-backed revocation service. Wraps `confium-tc`.

```rust
pub struct RevocationService {
    service_quorum: QuorumId,
    coordinator: CoordinatorHandle,
}

impl RevocationService {
    /// User-side: prepare a revocation blob for escrow.
    /// Encrypts (revocation_signature + public_key) to service quorum's
    /// threshold public key.
    pub fn prepare_revocation_blob(
        &self,
        revocation_sig: &[u8],
        public_key: &[u8],
        user_email: &str,
    ) -> Result<RevocationBlob>;

    /// Service-side: submit blob for processing.
    /// Triggers email verification + 24-hour delay (configurable) +
    /// threshold decryption ceremony.
    pub async fn submit(
        &self,
        blob: RevocationBlob,
        verification_token: VerificationToken,
    ) -> Result<SubmissionReceipt>;

    /// Service-side: process pending submissions after delay.
    /// Calls threshold_decrypt with service quorum.
    pub async fn process_pending(&self) -> Result<usize>;

    /// Service-side: publish a processed revocation.
    pub async fn publish(
        &self,
        submission: &SubmissionReceipt,
        keyservers: &[KeyserverUrl],
    ) -> Result<()>;
}
```

The threshold key replaces the single service decryption key in
Thunderbird's design. The two-phase commit (submit + 24-hour delay +
confirm) is preserved.

## What Confium adopts from Thunderbird's designs

| Concept | Adopted from | Confium use |
|---|---|---|
| Two-phase commit (submit + delay + confirm) | Revocation service | All sensitive quorum operations |
| Stateless service design | Revocation service | Coordinator service defaults to stateless |
| Email verification before crypto operation | Revocation service | Threshold session request validation |
| Per-account key scoping | Key backup | Per-actor key isolation in Mode 3 |
| Recovery keypair distinct from app keys | Key backup | Escrow keypair is separate from signing/encryption |
| Local signing subkey (`data-signkey`) | Key backup | Every artifact signed before encryption for tamper detection |
| Public key fingerprint in subject | Both | Quorum ID in coordinator session metadata |

## What Confium improves beyond Thunderbird's designs

| Limitation in Thunderbird design | Confium improvement |
|---|---|
| Single Thunderbird service = compelled revocation risk | T-of-N threshold across independent operators |
| Paper recovery code = single point of failure | T-of-N social/institutional recovery |
| Service key in one HSM | Threshold key across N HSMs (no single HSM compromise breaks system) |
| No transparency for revocation events | Every revocation in OTS-anchored Merkle transparency log |
| Limited audit trail | Every threshold ceremony fully audit-logged with custodian identity signatures |
| Ad-hoc two-party pattern | General T-of-N with attribute-based predicates |

## Standardization opportunity

The Thunderbird designs describe real-world patterns. Confium
generalizes them into framework primitives. This is itself a
research contribution:

- **Paper candidate**: "From Two-Party to T-of-N: Generalizing
  Thunderbird's Revocation and Recovery Designs with Threshold
  Cryptography" — analyzes the security improvements of the
  threshold generalization.

## Status

- `confium-patterns` (escrow): scaffold created, real implementation P0
- `confium-patterns` (revocation): scaffold created, real implementation P1
- BUGREPORTs filed at rnp-rs for related API gaps:
  - `BUGREPORT.threshold-share-key-import.md`
  - `BUGREPORT.pqc-keypair-with-signing-and-encryption-subkeys.md`
  - `BUGREPORT.detached-revocation-signature-helper.md`

## References

- [Thunderbird revocation service proposal](https://github.com/kaie/tb-misc/blob/main/revocation-service.md)
- [Thunderbird key backup and recovery strategy](https://github.com/kaie/tb-misc/blob/main/key-backup-recovery-strategy.md)
- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/31-threshold-encryption.md` — `confium-tc` (kem) interface
- `TODO.roadmap/29-tc-coordinator-design.md` — async ceremony
