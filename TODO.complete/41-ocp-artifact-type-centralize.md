# 41 — OCP violation fixes: centralize enum string conversion

## Problem

Several places across the workspace had `match` statements mapping
enum variants to/from strings. Every variant addition required
updating every match — classic OCP (Open-Closed Principle) violation.

Concrete example: `confium-python/src/transparency.rs` had two
18-line `match` blocks (one for parse, one for display) duplicating
the same 8 ArtifactType variants. The same string names also lived
implicitly in serde's `rename_all = "snake_case"` attribute on the
enum itself. Three places to update when adding a variant.

## What was done

### Centralized ArtifactType string conversion

Added to `confium-transparency/src/entry.rs`:

- `ArtifactType::as_str(self) -> &'static str` — the canonical
  snake_case name for each variant.
- `ArtifactType::ALL: &[ArtifactType]` — const slice of all
  variants in declaration order, for binding iterators and CLI
  argument completion.
- `impl std::fmt::Display for ArtifactType` — forwards to `as_str`.
- `impl std::str::FromStr for ArtifactType` — iterates `ALL` and
  compares. Returns `UnknownArtifactType` error on mismatch.
- `pub struct UnknownArtifactType` — typed error containing the
  unknown input and a help message listing valid names.

### Refactored Python binding

`crates/confium-python/src/transparency.rs`:

- Removed the 16-line `parse_artifact_type` match block. Replaced
  with `ArtifactType::from_str(s)` call.
- Removed the 10-line `artifact_type_str` match block. Replaced
  with `at.as_str()` call.

Net: -26 lines of duplicated match arms.

### Test coverage

Added 3 tests in `entry.rs`:
- `artifact_type_as_str_roundtrips` — every variant round-trips
  through `as_str` → `from_str`.
- `artifact_type_display_matches_as_str` — Display and as_str agree.
- `artifact_type_unknown_string_fails` — typed error returned,
  message contains the input and the list of valid names.

## Why this is OCP-compliant

Adding a new ArtifactType variant now requires:
1. Adding the variant to the enum.
2. Adding one arm to `as_str` (the single source of truth).
3. Adding the variant to the `ALL` const slice.

The `from_str` automatically picks up new variants via the `ALL`
slice. The Display impl is automatic. Every binding (Python, Ruby,
WASM, future Node.js) consumes the public `as_str` / `FromStr`
surface — no per-binding match to update.

## Verification

```sh
cargo build -p confium-transparency   # clean
cargo test -p confium-transparency    # 31 tests pass (28 + 3 new)
cargo clippy --workspace --all-targets  # 0 warnings
```

## Other OCP audits (no action needed)

Surveyed other potential OCP violations:
- `confium-composite/src/lib.rs`: `match verifier(...)` in the
  `verify` callback. NOT an OCP violation — the verifier is
  caller-supplied (open for extension by design).
- `confium-net-tcp`/`confium-net-quic`: `match scheme { "tcp4" =>
  ..., "tcp6" => ... }`. These are finite URI scheme sets — closed
  by design.
- `confium-tc-core/src/registry.rs`: `register_tc_scheme!` macro +
  `inventory`-based registration. Already OCP-compliant (the
  `SchemePlugin` author registers via macro; the framework doesn't
  enumerate schemes).

No other OCP violations warranting action.

## Status

Done. One OCP violation fixed, 3 tests added, 26 lines of
duplicated match arms removed.
