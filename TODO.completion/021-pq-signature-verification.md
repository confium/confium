# 021 — PQ signature verification

**Category**: Topical
**Severity**: High (the headline feature)
**Effort**: Large (depends on Rust PQ crates maturing)

## Problem

We say "PQ migration" but only Ed25519 + ECDSA-P256 verifiers exist.
ML-DSA-65 (FIPS 204) and SLH-DSA (FIPS 205) verifiers aren't wired in.
The actual PQ-migration story is incomplete.

## Acceptance criteria

- [ ] `Confium::Composite::Signature#verify` accepts an ML-DSA-65
     component via the [caller-supplied verifier callback](005-composite-verifier-callback.md).
- [ ] A pure-Rust ML-DSA-65 verifier crate is identified (or written)
     and added as an optional dep.
- [ ] WASM gains the same hook.
- [ ] Spec: composite signature with 1 Ed25519 + 1 ML-DSA-65 component
     verifies via both verifiers.
- [ ] Spec: composite signature with 1 Ed25519 + 1 ML-DSA-65 component
     fails when only Ed25519 is verified (and the ML-DSA-65 component
     has a bad signature).
- [ ] `docs/pq-migration/composite-signatures.md` explains the
     migration path.

## Anti-patterns

- "Use the NIST reference C implementation via FFI" — defeats the
  no-unsafe + no-C-deps rules. Pure Rust or nothing.
- Hardcoding ML-DSA-65 in the verifier dispatch — use the callback.

## Approach

1. **Evaluate crates**: `ml-dsa` (RustCrypto), `pqcrypto` (NIST
   reference wrappers). Pick the pure-Rust one.
2. Add as an **optional** dep of `confium-composite` behind a
   `pqc-ml-dsa-65` feature flag.
3. Republish `confium-composite` 0.4.0.
4. Ruby + WASM extensions opt into the feature; verifier dispatch
   handles ML-DSA-65 natively when the feature is on.

## Related

- [005-composite-verifier-callback.md](005-composite-verifier-callback.md) —
  caller-side escape hatch until the Rust crate is wired.
- [022-fips-140-mode.md](022-fips-140-mode.md) — FIPS validation needs
  PQ algorithms.
