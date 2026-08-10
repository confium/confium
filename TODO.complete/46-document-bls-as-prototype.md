# 46 — Document confium-tc-bls as research prototype

## Problem

`confium-tc-bls` advertises itself as "Threshold BLS signature for
cross-organization aggregation" but the actual implementation
**XOR-folds signature bytes** rather than combining them via the
BLS12-381 pairing. The XOR-fold is a well-known anti-pattern
(sponge attacks recover individual signatures from aggregates).

A consumer reading the crate doc could reasonably think this is
production-ready. It is not.

## What was done

Added a prominent **"⚠️ RESEARCH PROTOTYPE — NOT FOR PRODUCTION USE"**
section to `confium-tc-bls/src/lib.rs` that:

- Calls out that the aggregation is a mock.
- Lists what's NOT supported (real signature verification, real
  BLS12-381 pairing, standard-library interop).
- Lists what IS supported (API shape validation, coordinator
  integration testing, FFI smoke testing).
- Points to `TODO.roadmap/04-threshold-cryptography.md` for the
  real implementation work.

## Same pattern in other research crates

Surveyed the other research-grade crates — they already have
similar framing in their lib.rs docs:

- `confium-ring`: "research prototype (P3) ... long horizon beyond
  Q2 2027 NIST MPTS submission."
- `confium-tc-ml-kem`: needs the same treatment (deferred).
- `confium-tc-fhe-bfv`: needs the same treatment (deferred).
- `confium-tc-frost-ml-dsa-65`: needs the same treatment (deferred).

These will be addressed in follow-up TODOs.

## Verification

```sh
cargo build -p confium-tc-bls   # clean
cargo doc -p confium-tc-bls --no-deps  # renders the warning
```

## Status

Done. Real BLS implementation tracked separately.
