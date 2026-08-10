# 52 — Zeroize on Drop for core Share types

## Problem

`confium-tc-core::Share` and `confium-tc-frost-p256::shamir::Share`
held cryptographic secret bytes/scalars in memory without
implementing `Zeroize` or `Drop`. When these types went out of
scope, the secret data remained in heap memory until the allocator
reused the page — potentially seconds to minutes.

CMP20 and GG18 shares already had zeroize (via the `zeroize`
crate). The core framework share type and the FROST-P256 Shamir
share did not.

## What was done

### `confium-tc-core::Share`

Added a manual `impl Drop for Share` that calls
`zeroize::Zeroize::zeroize(&mut self.bytes)`. This wipes the
secret-encoded share bytes before freeing the Vec.

Added `zeroize = { workspace = true, features = ["zeroize_derive"] }`
to `confium-tc-core/Cargo.toml`.

Changed `into_bytes(self)` to `into_bytes(self) -> Vec<u8>` with
`.clone()` — can't move out of a type that implements Drop.
Slight performance cost (one extra allocation) but the security
benefit (zeroize-on-drop) outweighs it.

### `confium-tc-frost-p256::shamir::Share`

Added a manual `impl Drop for Share` that calls
`zeroize::Zeroize::zeroize(&mut self.y)` on the P-256 `Scalar`.
The scalar field holds the actual secret share value.

Added `zeroize = { workspace = true }` to
`confium-tc-frost-p256/Cargo.toml`.

### Architecture doc accuracy

`docs/architecture.mdx`:
- Fixed `confium-tc-coordinator` → `confium-coordinator` (old crate name).
- Fixed "Every crate carries `#![forbid(unsafe_code)]`" to
  accurately describe that most crates do, with documented exceptions.

## Remaining zeroize gaps

These types still lack zeroize-on-drop (lower priority — they hold
partial signatures or decryption shares, not long-lived secrets):

- `confium-tc-bls::Share`
- `confium-crypto-vss::PedersenShare`
- `confium-crypto-vss::PartialSig`
- `confium-privacy::{PrfShare, PrgShare, DecryptionShare}`
- `confium-tc-elgamal-p256::DecryptionShare`

## Verification

```sh
cargo build --workspace   # clean
cargo test --workspace    # 1703 passed, 0 failed
```

## Status

Done. Core framework Share and FROST-P256 Share now zeroize on drop.
