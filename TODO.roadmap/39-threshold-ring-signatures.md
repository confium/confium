# 39 — Threshold ring signatures (research)

## Purpose

For sensitive national-security type approvals, hide WHICH
directors signed. Public can verify the signature; watchdogs know
SOMETHING was signed; signer identities anonymized among the
eligible set; revealed only to designated auditor.

Currently no production-quality threshold ring signature
implementation exists. Confium's would be the first.

## Research frontier

This is genuinely long-horizon research. Not in scope for Q2 2027
NIST MPTS submission. Tracked as future research contribution,
paper #3 in academic plan.

## Cryptographic landscape

### Ring signatures (Rivest-Shamir-Tauman 2001)

N members form a "ring". Signer produces signature on behalf of
the ring without revealing which member. Verifier confirms some
ring member signed, but cannot identify which.

### Threshold ring signatures (Bender-Ostrovsky-Pinkas 2006)

T-of-N members collaborate to produce a ring signature. Verifier
confirms T ring members signed, but cannot identify which T.

### Confium extension: accountable confidentiality

Combine threshold ring signature with designated auditor:
- Public sees anonymous threshold signature
- Watchdogs see "T members of the BIML ring signed"
- Designated auditor (court, treaty body) can decrypt identity
  evidence to determine which T members

This composition is novel. Likely paper-worthy.

## Use cases for OIML/CNML

- **National-security instruments**: defense-related type approvals
  where signer identities are sensitive
- **Diplomatic-pressured approvals**: where revealing which
  directors approved could cause diplomatic incident
- **Whistleblower-protected reports**: lab reports where lab
  identity hidden from public

## Crate scope (future, P3)

### `confium-ring` (P3 — research)

```rust
pub struct RingSignature {
    pub ring_members: Vec<PublicKey>,        // all eligible signers
    pub signature: Vec<u8>,                  // anonymous signature
    pub signer_count: usize,                 // T (how many signed)
    pub auditor_evidence: Option<EncryptedEvidence>,
}

pub fn threshold_ring_sign(
    message: &[u8],
    ring_members: &[PublicKey],
    signer_keys: &[&SigningKey],             // T actual signers
) -> Result<RingSignature>;

pub fn verify_ring_signature(
    sig: &RingSignature,
    message: &[u8],
) -> Result<()>;

pub fn auditor_reveal(
    sig: &RingSignature,
    auditor_key: &AuditorKey,
) -> Result<Vec<SignerIdentity>>;
```

## Implementation challenges

- **Performance**: ring signatures are typically 10-100x slower
  than threshold signatures due to witness hiding
- **Size**: ring signatures are larger (linear in ring size)
- **Composability**: combining with threshold ceremony adds latency
- **Auditor accountability**: need to ensure auditor can identify
  signers WITHOUT enabling public identification

## Deployment phasing

- **Phase 1 (through 2027)**: standard threshold signatures,
  signer identities public in audit log. Sufficient for most
  OIML work.
- **Phase 2 (2028+)**: research threshold ring signature prototype.
  Deployed for sensitive classes only.
- **Phase 3 (2029+)**: production deployment if research matures.

## Out of scope for initial framework

Threshold ring signatures are research output, not framework
primitive. Tracked here for completeness; not blocking Q2 2027
NIST submission.

## References

- `TODO.roadmap/26-confium-framework.md`
- [Rivest-Shamir-Tauman 2001, "How to Leak a Secret"](https://people.csail.mit.edu/rivest/pubs/RST01.pdf)
- [Bender-Ostrovsky-Pinkas 2006, "Threshold Ring Signatures"](https://eprint.iacr.org/2005/395)
