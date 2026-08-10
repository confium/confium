# 51 — Convert confium-tc to facade of confium-tc-core

## Problem

`confium-tc` and `confium-tc-core` had **7 byte-identical modules**
(error, message, party, registry, session, share, share_envelope) —
the same code compiled twice. Scheme crates (CMP20, GG18, FROST)
depended on `confium-tc` for these; key-management crates
(`confium-tc-keys`, `confium-threshold`) depended on `confium-tc-core`.
Same types, different crate paths — a DRY violation.

## What was done

1. Added `confium-tc-core` as a dependency of `confium-tc`.
2. Replaced 7 module declarations in `confium-tc/src/lib.rs` with
   `pub use confium_tc_core::{module}` re-exports.
3. Replaced all type re-exports (`Error`, `Result`, `Message`, `Party`,
   `PartyList`, `RoundResult`, `SessionImpl`, `TcScheme`,
   `TcSchemeKind`, `Session`, `SessionParams`, `Share`) with
   `pub use confium_tc_core::{Type}`.
4. `git mv`'d the 7 duplicate source files to
   `crates/confium-tc/attic/facade-duplicates/`.
5. Kept `ffi` and `inprocess` as local modules in `confium-tc` —
   ffi uses unsafe (tc-core has `#![deny(unsafe_code)]`) and
   inprocess has tc-specific import paths.

## What did NOT change

- The public API of `confium-tc` is 100% backward-compatible. Every
  `use confium_tc::*` still resolves the same types.
- Scheme crates (CMP20, GG18, FROST-ed25519) that depend on
  `confium-tc` still compile unchanged.
- The `register_tc_scheme!` macro is `#[macro_export]`'d from
  tc-core; `confium-tc` re-exports it for back-compat.

## Impact

- **DRY**: 7 identical modules compiled once instead of twice.
- **Compile time**: incremental builds of `confium-tc` skip
  recompiling the session/error/party/etc. code (already compiled
  as part of `confium-tc-core`).
- **Maintainability**: editing a session bug now requires changing
  one file instead of two.
- **Test count**: tests in the 7 duplicate modules now run once
  (from tc-core) instead of twice. Workspace test count went from
  1730 → 1703 (the 27 duplicate tests are eliminated).

## Verification

```sh
cargo build --workspace          # clean
cargo test --workspace           # 1703 passed, 0 failed
cargo clippy --workspace --all-targets   # 0 warnings
```

## Status

Done. The facade conversion is complete for the 7 identical modules.
ffi and inprocess remain local pending unsafe-code policy decisions.
