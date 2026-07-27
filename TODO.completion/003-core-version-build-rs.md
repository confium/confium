# 003 — core_version via build.rs

**Category**: Architectural
**Severity**: Low
**Effort**: Small (1 PR)

## Problem

`Confium.core_version` is a hardcoded `"0.2.0"` string in the Rust
extension's `lib.rs`. It will silently drift the moment the gem is
built against a newer `confium-core` crate.

## Acceptance criteria

- [ ] `Confium.core_version` returns the actual `confium-core` crate
  version the extension was built against.
- [ ] The version is read at build time via a `build.rs` script that
  emits `cargo:rustc-env=CONFIUM_CORE_VERSION=X.Y.Z`.
- [ ] `lib.rs` reads `env!("CONFIUM_CORE_VERSION")`.
- [ ] One spec confirms the version matches the gemspec's
  `confium-core` dep version.

## Anti-patterns

- Hand-maintained constants that duplicate dep versions.
- Reading `Cargo.toml` at runtime — too slow.

## Approach

1. Add `ext/confium_native/build.rs` that:
   - Reads `Cargo.lock`
   - Finds the `confium-core` version
   - Prints `cargo:rustc-env=CONFIUM_CORE_VERSION=...`
2. Update `core_version()` to use the env var.
3. Wire `build = "build.rs"` into `ext/confium_native/Cargo.toml`.
