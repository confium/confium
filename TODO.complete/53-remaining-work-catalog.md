# 53 — Remaining work catalog: comprehensive audit

## Purpose

After completing TODOs 36-52 (plus the tc-facade, zeroize,
tc-core-orphans, getting-started, and doc-link work), this TODO
catalogs ALL remaining work items that would make the workspace
"done" for the current product phase (v0.4.x → v0.5).

Each item is prioritized P0 (must do before v0.5) through P3
(nice-to-have, can defer to v0.6+).

## P0 — Security and correctness

### 54. Zeroize remaining share types
8 secret-bearing types still lack zeroize-on-drop:
- `confium-tc-bls::Share`
- `confium-crypto-vss::PedersenShare`
- `confium-crypto-vss::PartialSig`
- `confium-privacy::{PrfShare, PrgShare, DecryptionShare}`
- `confium-tc-elgamal-p256::DecryptionShare`
- `confium-tc-core::NormalizedShare` (via share_adapter)

Each needs a manual `impl Drop` or `#[derive(ZeroizeOnDrop)]`.

### 55. Constant-time comparison audit
Check that all signature verification and scalar comparisons use
`subtle::ConstantTimeEq` rather than `==`. The `==` operator on
`Scalar` and `AffinePoint` (p256 crate) IS constant-time, but
`Vec<u8>` comparison is not. Any code comparing raw public keys,
signatures, or hashes for equality in a security-critical context
should use `subtle`.

## P1 — Architecture

### 56. Extract confium-tc coordinator/ to confium-coordinator
confium-tc/src/coordinator/ has a local coordinator module (6 files).
The separate confium-coordinator crate has 40+ modules. Eventually
scheme crates should depend on confium-coordinator, not confium-tc.

### 57. Add spec stub for confium-store
The store crate (compartmentalized backends: memory, PKCS#11, TPM,
cloud KMS, OpenPGP card) has no specification. A spec stub would
document the backend trait, compartment model, and FFI surface.

### 58. Add spec stub for confium-patterns
The patterns crate (threshold key escrow + revocation) has no spec.

## P2 — Testing

### 59. Property tests for confium-pki cert path validation
Add proptest that generates arbitrary cert chains and verifies
path validation handles edge cases (empty path, self-signed root,
expired intermediate, etc.).

### 60. More fuzz targets
confium-fuzz has 4 targets (composite_verify, inclusion_proof,
protocol_message, share_envelope). Could add:
- `fuzz_cms_signed_data` — malformed CMS input.
- `fuzz_attributes_predicate` — adversarial DSL input.
- `fuzz_merkle_proof` — proof with wrong direction bits.

## P3 — Performance and polish

### 61. MerkleTree inclusion_proof caching
`inclusion_proof(seq)` is O(N) per call (rebuilds the tree from
leaves). Could cache intermediate levels and make it O(log N).

### 62. CMP20 batch signing optimization
`inprocess::sign()` builds N sessions, drives N rounds, then
aggregates. For batch signing (100 messages in sequence), the DKG
output is reused but sessions aren't. Could add a batch-sign API
that amortizes session setup.

## Status

Living document — items are checked off as they're completed.
