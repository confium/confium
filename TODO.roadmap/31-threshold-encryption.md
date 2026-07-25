# 31 — Threshold encryption

## Purpose

Threshold encryption is the co-equal of threshold signing. Anyone
can encrypt to a public key; T-of-N parties collaborate to decrypt.

Without threshold encryption, the framework only solves half the
problem. Confidential data sent to an institution must be readable
only via quorum ceremony, not by a single party.

## Use cases

- **Confidential archival**: lab test reports sealed to BIML quorum
  for decades. Decryptable only via T-of-N ceremony.
- **Sealed evidence**: revocation evidence threshold-encrypted,
  revealed only on court order via quorum.
- **Cross-tier escalation**: IA encrypts sensitive data to BIML
  quorum; only BIML threshold can decrypt.
- **Key escrow**: end-entity signer keys escrowed to quorum for
  recovery.
- **Browser-side encryption**: labs encrypt test reports in
  browser to IA threshold public key.

## Architecture

Threshold encryption is a 2-phase protocol:

```
Phase 1: Encapsulation (anyone can do this, no coordination)
  - Encryptor runs KEM encapsulate against threshold public key
  - Produces (encapsulated_key, ciphertext)
  - Encapsulated_key is a "partial" — needs T parties to reconstruct

Phase 2: Decapsulation (T-of-N parties collaborate)
  - Each of T parties computes partial decapsulation from their share
  - Coordinator aggregates T partials → full shared secret
  - Shared secret + ciphertext → plaintext (via AEAD)
```

This mirrors threshold signing's session lifecycle.

## Crate scope

### `confium-tc-kem` (P0 — interface)

Threshold KEM session interface, parallel to `confium-tc` for
signing.

```c
// Encapsulator-side (anyone)
uint32_t cfmp_tc_kem_encapsulate(
    const uint8_t *recipient_public_key, size_t pk_len,
    uint8_t **encapsulated_key_out, size_t *ek_len_out,
    uint8_t **shared_secret_out, size_t *ss_len_out);

// Decapsulator-side (T-of-N threshold session)
uint32_t cfmp_tc_kem_session_create(
    FFITcKemSession **out,
    const char *scheme,                  // "ElGamal-P256-threshold", "ML-KEM-768-threshold"
    const CFMTcPartyList *parties,
    uint32_t threshold,
    uint32_t this_party_idx,
    const CFMTcShare *local_share,
    const Option *opts);

uint32_t cfmp_tc_kem_session_round(
    FFITcKemSession *s,
    const CFMTcMessage *incoming, uint32_t incoming_count,
    CFMTcMessage **outgoing, uint32_t *outgoing_count,
    uint8_t *complete,
    const Option *opts);

uint32_t cfmp_tc_kem_session_result(
    FFITcKemSession *s,
    uint8_t *out, uint32_t out_max, uint32_t *out_len);

uint32_t cfmp_tc_kem_session_destroy(FFITcKemSession *s);

// DKG (parallel to signing DKG)
uint32_t cfmp_tc_kem_dkg_output_share(
    FFITcKemSession *s,
    CFMTcShare **share_out,
    uint8_t *public_key_out, uint32_t pk_max, uint32_t *pk_len);
```

### `confium-tc-elgamal-p256` (P1)

Threshold ElGamal over P-256. Mature, well-analyzed. Suitable for
medium-term sealed data (5-10 year appeals window).

### `confium-tc-ecies-p256` (P2)

Threshold ECIES for browser key escrow. Each browser-held key
encrypted under threshold ECIES public key; recoverable via quorum.

### `confium-tc-ml-kem` (P1 — research frontier)

**No production-quality threshold ML-KEM exists today.** This
crate would be the first. Based on FIPS 203 (ML-KEM / Kyber).

Research questions:
- Proactive share refresh for lattice schemes
- Threshold decryption ceremony with audit trail
- Re-encryption for quorum composition changes
- Composition with AEAD for symmetric encryption of actual data
- Cross-tier re-encryption (IA → BIML without plaintext exposure)

This crate ships as research prototype; production use requires
academic collaborator engagement (see `TODO.roadmap/26`).

### `confium-tc-fhe-bfv` (P3 — research)

Threshold BFV FHE. Allows computation on encrypted data without
decryption. For OIML: statistical analysis of test reports without
revealing individual reports.

Long horizon. Separate research track.

## Hybrid encryption pattern

Threshold KEM produces a shared secret. Actual data encrypted with
AEAD using shared secret as key. Standard hybrid:

```rust
// Encryptor
let (encapsulated_key, shared_secret) = kem.encapsulate(recipient_pk)?;
let ciphertext = aead.encrypt(&shared_secret, plaintext)?;

// Transmit: (encapsulated_key, ciphertext, aad)

// Decryptor (T-of-N quorum)
let shared_secret = threshold_decapsulate(encapsulated_key)?; // coordinator-managed
let plaintext = aead.decrypt(&shared_secret, ciphertext)?;
```

The KEM shared secret is short (32 bytes). The AEAD handles
arbitrary-length plaintext. Standard, well-analyzed.

## Selective disclosure

Each artifact encrypted to a specific recipient quorum's public key:

- Test report → IA threshold public key (one IA, not all IAs)
- Escalation → BIML threshold public key
- Sealed evidence → BIML threshold public key + court-order tag

Public keys published in deployment manifest (`TODO.roadmap/33-config-manifest.md`).

## Security

- Threshold property: T-1 parties cannot decrypt
- Proactive refresh: monthly share refresh invalidates prior compromises
- Audit: every decryption ceremony logged with director signatures
- Compromise recovery: re-share to new committee, old shares destroyed

## Performance

| Operation | Wall time (target) |
|---|---|
| Encapsulate (encrypt) | <10ms |
| Threshold decapsulate (3-of-5 P-256) | <500ms |
| Threshold decapsulate (5-of-7 ML-KEM-768) | <2s (research estimate) |
| Re-encrypt archive (1M docs, ML-KEM) | minutes (background) |

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/30-tc-reshare-protocol.md` — share refresh applies to KEM shares
- [FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [Shoup, "Practical Threshold Signatures," EUROCRYPT 2000](https://www.shoup.net/papers/thresh.ps)
