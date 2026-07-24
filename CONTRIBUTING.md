# Contributing to Confium

Thank you for your interest in contributing to Confium! This document covers
the basics. For design context, see `README.adoc`.

## Development Setup

Confium requires a stable Rust toolchain (1.85+ for edition 2024). The
toolchain is pinned via `rust-toolchain.toml`. To enter a Nix-based dev
shell with all dependencies:

```sh
nix develop
```

Or install Rust directly via [rustup](https://rustup.rs/).

## Common Commands

```sh
cargo build                  # build the cdylib
cargo test                   # run unit tests
cargo fmt --all              # format code
cargo clippy --all-targets -- -D warnings   # lint
cargo doc --no-deps          # build docs
cargo deny check             # license/advisory/ban checks
typos                        # spell check
```

C++ binding tests live in `cpp-tests/` and require CMake, cbindgen, and Boost:

```sh
mkdir build && cd build
cmake -DBUILD_TESTING=yes -DBUILD_C_BINDINGS=yes ..
cmake --build .
ctest -C Debug -V
```

## Pre-commit Hooks

Two options are available; both mirror CI:

- Framework version (requires `pip install pre-commit`):

  ```sh
  pre-commit install
  ```

- Shell version (no dependencies):

  ```sh
  cp .githooks/pre-commit .git/hooks/pre-commit
  chmod +x .git/hooks/pre-commit
  ```

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Use [conventional commit](https://www.conventionalcommits.org/) messages
   (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`, `chore:`). These
   drive automated versioning via release-plz.
3. Ensure CI is green locally and on the PR.
4. Breaking changes must include `!` (e.g. `feat!: ...`) and a migration note.

## Releases

Releases are automated. Merging to `main` triggers `release-plz`, which opens
a release PR with the version bump and changelog. Merging that PR publishes
to crates.io.

Never push tags directly. The bot handles it.
