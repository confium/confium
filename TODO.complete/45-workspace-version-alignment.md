# 45 — Fix workspace version inconsistency

## Problem

8 crates pinned `version = "0.4.0"` (or `0.4.7` for confium-wasm)
hard-coded in their own Cargo.toml instead of inheriting from the
workspace. The workspace is at `0.4.7`:

- confium-attributes 0.4.0
- confium-composite   0.4.0
- confium-core        0.4.0
- confium-node        0.4.0
- confium-pki         0.4.0
- confium-python      0.4.0
- confium-transparency 0.4.0
- confium-wasm        0.4.7 (still out of sync with workspace)

Result: publishing the workspace would publish these 8 crates at
inconsistent versions relative to the rest of the workspace (which
inherits from `[workspace.package] version = "0.4.7"`).

## What was done

Replaced `version = "0.4.x"` with `version.workspace = true` in all
8 crates. Now every crate in the workspace inherits from
`[workspace.package]` in the root Cargo.toml.

## Why this matters

- A single source of truth for the version (workspace root).
- `release-plz` and `cargo release` work correctly — bumping the
  workspace version propagates to every crate.
- crates.io publishes happen at consistent versions.
- No more "why is confium-pki 0.4.0 but confium-tc-cmp20 0.4.7?"
  confusion for downstream consumers.

## Verification

```sh
cargo build --workspace   # clean
grep -E '^version = "' crates/*/Cargo.toml  # no hits — all use workspace = true
```

## Status

Done.
