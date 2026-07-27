# 023 — Test vector verification

**Category**: Topical
**Severity**: High (single-point-of-failure risk without it)
**Effort**: Medium (1 PR per source)

## Problem

Unit tests in the Rust crates exercise happy paths but don't verify
against external test-vector corpora. Wycheproof, NIST CAVP, Project
Wycheproof — none are wired up. A subtle implementation bug could pass
our tests and still produce bad signatures.

## Acceptance criteria

- [ ] `tests/vectors/wycheproof/` checked in (or pulled from upstream
     on test-run via `build.rs`).
- [ ] Per-algorithm test runner:
  - `tests/vectors/ed25519_wycheproof.rs` — runs every Wycheproof
    Ed25519 vector through `ed25519-dalek` via confium-composite.
  - `tests/vectors/p256_wycheproof.rs` — same for ECDSA-P256.
  - `tests/vectors/nist_cavp_sha2.rs` — NIST CAVP SHA-2 vectors through
    the hash plugin path.
- [ ] CI runs these on every PR.
- [ ] Failures block merge.
- [ ] Ruby/WASM specs pick a representative subset (10-20 vectors) and
     exercise them end-to-end through the binding.

## Anti-patterns

- "We trust the upstream Rust crates" — bugs happen at integration
  boundaries.
- Hand-rolling test vectors — always use canonical sources.

## Approach

Vendor Wycheproof via git submodule. NIST CAVP via direct download
(parsing their `.rsp` format). For each algorithm, a thin Rust test
runner iterates the vectors and asserts.

## Related

- [020-nist-mpts-harness-bindings.md](020-nist-mpts-harness-bindings.md) —
  NIST MPTS is a specific threshold-focused evaluation.
