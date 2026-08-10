# 39 — Doc-test examples for public APIs

## Problem

Public API entry points (composite, transparency, pki, frost-p256,
cmp20, privacy) had rich crate-level documentation but no runnable
`cargo test --doc` examples. Doc examples are verified by rustc at
test time — they catch:
- API drift (a method renamed in code but not in docs)
- Hallucinated APIs (a doc that references a method that doesn't exist)
- Compilation regressions from refactoring

## What was added

Single end-to-end example per crate lib.rs, demonstrating the
primary use case. Each example:
- Compiles against the public API surface
- Runs without panicking
- Returns `Result<...>` so the `?` operator verifies error types

### `confium-transparency/src/lib.rs`

Merkle tree append + inclusion proof round-trip. Verifies
`MerkleTree::new`, `append`, `root`, `inclusion_proof`,
`verify_inclusion`, and the `MerkleError` type.

### `confium-composite/src/lib.rs`

Ed25519 component sign + JSON round-trip + verify. Verifies
`build_ed25519_component`, `CompositeSignature::new`, `verify`,
`ed25519_verifier`, `VerificationResult::all_verified`.

### `confium-pki/src/lib.rs`

`VerificationResult::aggregate` happy + failure path. Verifies the
`result::VerificationResult` API and the `PathFailure::Expired`
enum variant.

### `confium-tc-frost-p256/src/lib.rs`

Shamir secret sharing round-trip: keypair → split → take T →
recover. Verifies `generate_keypair`, `split_secret`,
`recover_secret`, and the `ShamirError` type.

### `confium-tc-cmp20/src/lib.rs`

Threshold DKG + sign via the inprocess driver. Verifies
`inprocess::keygen`, `inprocess::sign`, and the `confium_tc::Error`
type.

### `confium-privacy/src/lib.rs`

Differential privacy query. Verifies
`privacy_and_dist_patterns::dp_query`.

## Verification

```sh
cargo test --doc --workspace   # 15 doctests pass
```

(Each crate-level doctest runs as a separate `cargo --doc` target
and is gated by the CI `Format and Lint` job via `cargo doc
--workspace --no-deps`.)

## Status

Done. 5 new doctests across the most-imported public API crates.
