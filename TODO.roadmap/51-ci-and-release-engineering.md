# 51 — Continuous integration and release engineering

## CI workflows

### `.github/workflows/ci.yml` (existing, the workhorse)

Runs on every PR + push to main. Gates:
- `typos` spell check
- `cargo audit` (RustSec advisories)
- `cargo deny check` (licenses, advisories, sources, bans)
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo doc --workspace --no-deps`
- `cargo machete` (unused dependencies)
- `cargo test --workspace` on Linux + macOS + Windows
- C++ binding tests on Linux + macOS (Windows dropped per MarkusJx issues)
- Semver checks via `cargo semver-checks`

### `.github/workflows/release.yml` (existing, release-plz)

On push to main: release-plz opens a "release PR" with version bumps
driven by conventional commits. On merge of that PR:
- crates.io publish for every bumped crate
- GitHub tag created
- CHANGELOG.md updated

### `.github/workflows/rustdoc.yml` (shipped)

On push to main: builds RustDoc for all workspace crates, deploys to
GitHub Pages at `rustdoc.confium.org`.

### `.github/workflows/release-binary.yml` (shipped)

On tag push (`v*.*.*`): builds static `confium` CLI binaries for
Linux x86_64+aarch64 (musl), macOS x86_64+aarch64, Windows x86_64.
Uploads to GitHub Release.

### `.github/workflows/wasm.yml` (shipped)

On tag push: builds `confium-sandbox-wasm` and publishes to npm as
`@confium/confium-wasm`.

## CI matrix

### Rust version matrix

```yaml
strategy:
  matrix:
    rust: [stable, beta, "1.85"]  # 1.85 = MSRV
```

Beta catches regressions early; 1.85 verifies MSRV stays put.

### OS matrix

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
```

Windows may be skipped for tests requiring PCSC (smartcard), CryptoAPI,
or system PKCS#11 modules.

### Architecture matrix

For release binaries: x86_64 + aarch64 on Linux and macOS.
Cross-compile via `dtolnay/rust-toolchain` with target list.

## Caching

- `Swatinem/rust-cache@v2` for `~/.cargo` and `target/`
- Per-job cache key includes: branch, Cargo.lock hash, rustc version
- Separate caches per OS to avoid cross-platform contamination

## Required checks

PRs to `main` require passing:
- `cargo test --workspace` (Linux)
- `cargo clippy` clean
- `cargo fmt --check` clean
- `cargo deny check` clean
- `typos` clean
- All status checks via branch protection rules

## Branch protection

`main` is protected:
- Required reviews: 1 (Ribose team)
- Required status checks: all listed above
- Dismiss stale reviews on new push
- Require linear history (rebase, no merge commits)
- Restrict force-push
- Restrict deletion

## Release cadence

- **Patch** (0.3.0 → 0.3.1): bug fixes only. No API changes. Often.
- **Minor** (0.3.x → 0.4.0): new features, new interfaces. Backward-compatible API.
- **Major** (0.x → 1.0.0): breaking API changes. Reserved for milestone moments.

Conventional commits drive the bumps automatically via release-plz:

- `feat:` → minor
- `fix:` → patch
- `feat!:` or `fix!:` → major
- `docs`, `chore`, `refactor`, `test`, `ci` → no bump (changelog only)

## Rollback strategy

- crates.io: yank the version (doesn't remove, but breaks build for new users)
- GitHub Release: convert to draft, retag previous version
- Branch: revert the merge commit, push, release-plz bumps to next patch
- Document in CHANGELOG as `## [Unreleased]` → `## [Yanked]`

## Anti-goals

- **Not** running benchmarks in CI gating (too noisy)
- **Not** requiring green CI for direct pushes (only PRs)
- **Not** supporting multiple Rust nightly versions (stable + beta only)

## References

- `TODO.roadmap/44-benchmark-suite.md` — CI for benchmarks
- `.github/workflows/` — actual workflow files
