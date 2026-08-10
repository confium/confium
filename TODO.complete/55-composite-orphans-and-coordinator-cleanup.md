# 55 — Declare orphaned composite modules + move 26 coordinator orphans to attic

## Problem

Two more DRY/dead-code issues found:

1. **confium-tc/src/coordinator/** had 26 submodules that were NOT
   declared in `coordinator/mod.rs`. These are near-duplicates of the
   modules in the separate `confium-coordinator` crate. The tc versions
   were never compiled.

2. **confium-composite/src/** had 5 orphaned files (`cache.rs`,
   `cose.rs`, `pq.rs`, `proptest.rs`, `wycheproof.rs`) with real
   functionality (256-461 lines each) that were never declared in
   `lib.rs`.

## What was done

### confium-tc coordinator orphans (26 files → attic)

`git mv`'d all 26 undeclared coordinator submodules to
`crates/confium-tc/attic/coordinator-orphans/`. The live versions
are in `crates/confium-coordinator/src/coordinator/`.

### confium-composite orphaned modules (3 declared, 2 left orphaned)

Declared 3 orphaned modules in `confium-composite/src/lib.rs`:

- **`pub mod cache`** — LRU verification cache (256L, 7 tests).
  Thread-safe `Mutex<HashMap>` with LRU eviction.
- **`pub mod cose`** — COSE_Sign1 CBOR wrapper (461L, multiple tests).
  RFC 8152 compliant encoding/decoding with a custom CBOR reader.
- **`pub mod pq`** — PQ composite helpers (104L).
  Algorithm identifier constants for ML-DSA / SLH-DSA composites.

Left orphaned (intentionally):
- `proptest.rs` — has compilation issues (references items not in scope).
  Will be fixed in a follow-up.
- `wycheproof.rs` — gated behind `#![cfg(feature = "wycheproof")]`
  but no such feature exists. Needs a feature declaration or
  restructuring as a test-only module.

### Fixed cose dead-code warning

`CborReader::peek()` method was never called — added `#[allow(dead_code)]`
since it's part of the API surface for future consumers.

## Impact

- **26 dead coordinator duplicate files** eliminated from the source tree.
- **3 modules with 26 tests** brought online (cache: 7, cose: ~19).
- Workspace test count: 1742 → 1768.
- 0 clippy warnings.

## Verification

```sh
cargo build --workspace          # clean
cargo test --workspace           # 1768 passed, 0 failed
cargo clippy --workspace --all-targets   # 0 warnings
```

## Status

Done.
