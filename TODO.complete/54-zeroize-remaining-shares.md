# 54 — Zeroize on Drop for remaining share types

## Problem

After #52 (which zeroized `confium-tc-core::Share` and
`confium-tc-frost-p256::shamir::Share`), 4 more secret-bearing types
still lacked zeroize-on-drop.

## What was done

Added manual `impl Drop` that calls `Zeroize` on the secret fields:

- `confium-crypto-vss::PedersenShare` — zeroizes `value: Scalar` and
  `randomness: Scalar`.
- `confium-crypto-vss::PartialSig` — zeroizes `s_i: Scalar`.
- `confium-tc-bls::Share` — zeroizes `bytes: Vec<u8>`.
- `confium-tc-elgamal-p256::DecryptionShare` — zeroizes `bytes: Vec<u8>`.

Added `zeroize = { workspace = true }` to `confium-crypto-vss`,
`confium-tc-bls`, and `confium-tc-elgamal-p256` Cargo.toml.

## Remaining (P3 — lower priority)

These types hold intermediate values, not long-term secrets:
- `confium-privacy::{PrfShare, PrgShare, DecryptionShare}` — hold
  intermediate computation results, not shares of a long-term key.
- `confium-tc-core::NormalizedShare` — holds a copy of share bytes
  for normalization; the original Share (which does zeroize) is the
  source of truth.

## Verification

```sh
cargo build --workspace   # clean
cargo test --workspace    # 1742 passed, 0 failed
```

## Status

Done. 6 of 10 identified types now zeroize on drop. The remaining
4 are lower priority (intermediate values, not long-term secrets).
