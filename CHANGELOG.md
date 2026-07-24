# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases prior to 0.2.0 were tracked through git history.

## [0.2.0] — Unreleased

### Breaking changes

The Rust API surface changed (the crate is `cdylib`-only, so no external Rust
consumers are affected; the C ABI is unchanged):

- Removed `Confium::new_custom` (slog-backed; the `logger` field is gone).
- Renamed `Hash::clone` → `Hash::try_clone` to avoid shadowing the `Clone` trait.

### Changed

- Migrated from Rust nightly to stable. The crate previously required nightly
  for `#![feature(let_chains)]`, but the feature was declared and never used.
- Bumped Rust edition from 2018 to **2024** (requires rustc 1.85+).
- Bumped `libloading` from 0.7 to 0.8.
- Bumped `snafu` from 0.6 to 0.8. Context structs now require the `Snafu`
  suffix (e.g. `NullPointerSnafu`) and the `Error` suffix is stripped from
  variant names (e.g. `PluginInternalError` → `PluginInternalSnafu`).
- All `#[no_mangle]` attributes converted to `#[unsafe(no_mangle)]` per
  Rust 2024's unsafe-attribute requirement.

### Removed

- `slog`, `slog-async`, `slog-stdlog`, and `slog-term` dependencies. The
  `logger` field on `Confium` was never read and no log calls existed in
  the crate. `Confium::new_custom` was removed; use `Confium::new`.
- `#![feature(let_chains)]` declaration (unused).

### Added

- `rust-toolchain.toml` pins stable Rust with `rustfmt` and `clippy`.
- `deny.toml` configures cargo-deny for license, advisory, and ban checks.
- `typos.toml` configures the typos spell checker with project vocabulary.
- `release-plz.toml` enables automated versioning and changelog generation.
- `CONTRIBUTING.md` and `SECURITY.md`.
- `.pre-commit-config.yaml` and `.githooks/pre-commit` mirror CI locally.
- Comprehensive CI pipeline: typos, security audit, format/lint, unused
  dependency check, multi-platform Rust tests, C++ binding tests, semver
  checks. Replaces the deprecated `actions-rs/*`-based workflow.

### Fixed

- Resolved all `cargo build` warnings (unused imports, unused variables,
  dead `initialize` field on `PluginV0`, redundant `unsafe` blocks, etc.).
- `Hash::clone` renamed to `Hash::try_clone` to avoid shadowing the
  `Clone` trait method.
