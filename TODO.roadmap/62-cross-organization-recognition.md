# 62 — Cross-organization recognition (OIML MAA pattern)

## Background

OIML operates the Mutual Acceptance Arrangement (MAA): a certificate
issued by one Issuing Authority (IA) is recognized by other IAs without
re-testing. Currently this is administrative — Confium generalizes to
cryptographic recognition.

The pattern is broader than OIML: any federation of organizations that
mutually recognize each other's certifications needs this.

## Use cases

### Case A: OIML MAA (CNML certificates)

IA-France issues a CNML for an instrument model. IA-Germany, IA-Japan,
etc. recognize the certificate without re-issuance. The manufacturer
gets one signature that's valid in all participating jurisdictions.

### Case B: Accreditation bodies

A lab accredited by APLAC member X is recognized by APLAC member Y. Test
reports signed by X's accredited labs are accepted by Y.

### Case C: Standards body co-publication

ISO and IEC jointly publish a standard. Both organizations' thresholds
co-sign the publication.

## Cryptographic patterns

### Pattern 1: Multi-signature (independent signatures on same artifact)

Each recognizing IA signs the certificate independently. Verifier checks
all signatures; certificate valid if at least one IA's signature is from
a recognized jurisdiction.

```
cert = SignedCNML { payload, signatures: [sig_ia_france, sig_ia_germany, sig_ia_japan] }
```

Pros: simple, no coordination. Cons: large artifact (one signature per IA).

### Pattern 2: BLS aggregate signature

All recognizing IAs use BLS; their individual signatures aggregate into
one short signature (96 bytes on BLS12-381). Verifier checks aggregate
against aggregate public key.

```
cert = SignedCNML { payload, aggregate_signature: BLS-96-bytes }
aggregate_pubkey = Sum(ia_france_pubkey, ia_germany_pubkey, ia_japan_pubkey)
```

Pros: compact. Cons: requires all IAs to use BLS; identifies participating set.

### Pattern 3: Threshold-over-quorums

A meta-quorum of IA quorums collectively signs. Each IA runs its own
threshold signing; their outputs are combined.

```
meta_quorum = { ia_france_quorum, ia_germany_quorum, ia_japan_quorum }
meta_signature = aggregate(meta_quorum.sign(message))
```

Pros: very strong security (any T-of-N within any participating IA
quorum can sign; M-of-K IA quorums must participate). Cons: complex.

### Pattern 4: Cross-certification chain

Each IA certifies the others' threshold public keys via cross-signing.
The original issuer's signature is verifiable under any IA's recognized
key.

```
IA-France issues CNML → CNML signed by IA-France threshold key
IA-Germany cross-signs IA-France's threshold pubkey cert
Verifier can validate via either IA-France's direct cert OR IA-Germany's cross-cert
```

Pros: backward-compatible with single-issuer model. Cons: certificate
chain complexity.

## Recommendation

Pattern 4 (cross-certification chain) as the default for backward compat.
Pattern 2 (BLS aggregate) as the high-performance option for MAA deployments.

## Architecture

### Manifest extension

```toml
[recognition]
type = "cross_certification"  # or "bls_aggregate" or "threshold_meta"
peers = ["ia-germany", "ia-japan", "ia-usa"]
cross_signed_by = ["ia-germany", "ia-japan"]
```

### Verifier behavior

```rust
match recognition.type {
    CrossCertification => {
        // Try issuer's direct cert first
        // Fall back to peer cross-certs if direct fails
    }
    BlsAggregate => {
        // Verify aggregate signature against aggregate pubkey
    }
    ThresholdMeta => {
        // Verify meta-quorum signature
    }
}
```

## Anti-goals

- **Not** a "global PKI" — each IA keeps its own root; recognition is opt-in
- **Not** automatic — recognition requires explicit cross-certification agreement
- **Not** anonymous — participating IAs are publicly identified in manifest

## References

- `TODO.roadmap/27-cnml-deployment.md`
- `TODO.roadmap/26-confium-framework.md`
- [OIML MAA](https://www.oiml.org/maa)
