# 35 — Post-quantum composite signatures

## Purpose

PQ migration without breaking existing verifiers. Composite
signatures combine classical (Ed25519, ECDSA) and PQ (ML-DSA,
SLH-DSA) algorithms so breaking either alone doesn't break the
composite.

For Mode 2 deployments, this is the killer feature: enterprises
facing PQ migration can deploy Confium and get a software-only
migration path.

## Composite signature model

A composite signature is a single signature object containing
multiple component signatures over the same message. Verifier
validates all components; signature valid iff all valid.

```
CompositeSig {
   algorithm_ids: [Ed25519, ML-DSA-65],
   public_keys: [Ed25519_pub, ML-DSA-65_pub],
   signatures: [Ed25519_sig, ML-DSA-65_sig],
}
```

### Threshold composite

Each component is independently threshold-signed:

- FROST-Ed25519 produces Ed25519_sig (threshold T-of-N)
- FROST-ML-DSA-65 produces ML-DSA-65_sig (threshold T-of-N, possibly
  different T or N)
- Both assembled into composite

Two DKG ceremonies per quorum (one per algorithm). Both public keys
bound to single X.509 certificate via composite extension.

## IETF COMPOSITE SIG draft

Track the standardization. Current draft proposes specific algorithm
combinations:

- `id-MLDSA65-Ed25519` (target for OIML/CNML)
- `id-MLDSA65-ECDSA-P256`
- `id-MLDSA87-ECDSA-P384`
- `id-SLHDSA-SHA2-128S-Ed25519`
- ... (more)

Implement composite matching current draft. Re-version if draft
changes. Final FIPS 800-208A expected ~2027.

## Crate scope

### `confium-composite` (P1)

```rust
pub struct CompositeSignature {
    pub components: Vec<ComponentSignature>,
}

pub struct ComponentSignature {
    pub algorithm: SignatureAlgorithm,
    pub public_key: PublicKey,
    pub signature: Vec<u8>,
}

pub fn build_composite(
    message: &[u8],
    signers: &[ComponentSigner],
) -> Result<CompositeSignature>;

pub fn verify_composite(
    composite: &CompositeSignature,
    message: &[u8],
    trusted_roots: &[Certificate],
) -> Result<VerificationResult>;
```

Threshold-aware: `ComponentSigner` can be a single-party signer OR
a threshold signer (uses `confium-tc` session underneath).

### `confium-tc-frost-ml-dsa-65` (P1 — research)

Threshold FROST over ML-DSA-65. Lattice-based threshold signature.
Boneh et al. 2024 paper basis. Research prototype.

This is genuinely at the research frontier. Production deployment
requires academic collaborator engagement.

## Migration path

Phased PQ migration via composite:

| Phase | Composite | Classical-only verifiers | PQ-aware verifiers |
|---|---|---|---|
| Phase 1 (2026-2027) | Ed25519 + ML-DSA-65 | Verify Ed25519, ignore PQ | Verify both |
| Phase 2 (2028-2030) | Ed25519 + ML-DSA-65 (default) | Warn on missing PQ | Verify both |
| Phase 3 (2030+) | ML-DSA-65 only | Reject (no classical) | Verify PQ only |

Phase boundaries driven by NIST PQ migration guidance. Confium's
`pqc_migration` manifest section expresses the current phase.

## Threshold-specific PQ challenges

Lattice-based signatures (ML-DSA, ML-KEM, SLH-DSA) have different
algebraic structure than discrete-log signatures. Threshold variants:

- **FROST-ML-DSA**: lattice-based FROST. State-of-art research.
  Non-trivial because ML-DSA's signing is more complex than
  Schnorr/Ed25519.
- **Threshold ML-KEM**: lattice-based threshold KEM. Slightly
  easier than ML-DSA (decryption is conceptually simpler).
- **SLH-DSA**: stateful hash-based signatures; threshold variants
  even more research-stage.

For Mode 2 deployments, threshold ML-DSA-65 is the priority
(it's the NIST-recommended general-purpose PQ signature).

## Why composites matter for Confium adoption

Enterprises face the PQ migration cliff:

- **Without Confium**: replace all HSMs (years of vendor work),
  re-issue all credentials, re-do threshold protocols per algorithm.
- **With Confium**: software upgrade. PKCS#11 interface unchanged.
  Composite signatures maintain back-compat with classical verifiers
  during transition.

This is the single strongest enterprise sales pitch.

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/28-mode2-pki-replacement.md`
- [IETF LAMPS COMPOSITE SIG draft](https://datatracker.ietf.org/wg/lamps/documents/)
- [NIST PQC migration guidance](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [Boneh et al., "Threshold Lattice Signatures," 2024]
