# Completion Plan — Confium Bindings Gaps

Living index of all identified gaps in the Ruby + WASM binding surfaces.
Each entry points to a dedicated TODO file with problem statement,
acceptance criteria, and code-quality requirements.

**Numbering convention**: `NNN-slug.md`. Grouped by category; numbered
monotonically across the whole plan.

**Status legend**: ⏳ pending · 🚧 in-progress · ✅ done · ➖ N/A by design.

## Architectural (001–005)

| # | Slug | Status |
|---|---|---|
| [001](001-typed-error-hierarchy.md) | typed-error-hierarchy | ⏳ |
| [002](002-dry-p256-verifier.md) | dry-p256-verifier | ⏳ |
| [003](003-core-version-build-rs.md) | core-version-build-rs | ✅ |
| [004](004-cms-per-signer-resolution.md) | cms-per-signer-resolution | ⏳ |
| [005](005-composite-verifier-callback.md) | composite-verifier-callback | ⏳ |

## Functional (006–011)

| # | Slug | Status |
|---|---|---|
| [006](006-certificate-issuance.md) | certificate-issuance | ⏳ |
| [007](007-cms-signing.md) | cms-signing | ⏳ |
| [008](008-certificate-path-validation.md) | certificate-path-validation | ⏳ |
| [009](009-multi-party-tc-sessions.md) | multi-party-tc-sessions | ⏳ |
| [010](010-consistency-proofs.md) | consistency-proofs | ⏳ |
| [011](011-ots-ers-exposure.md) | ots-ers-exposure | ⏳ |

## Usability (012–016)

| # | Slug | Status |
|---|---|---|
| [012](012-enum-mixins.md) | enum-mixins | ⏳ |
| [013](013-structured-error-context.md) | structured-error-context | ⏳ |
| [014](014-wasm-leaf-hash-helper.md) | wasm-leaf-hash-helper | ✅ |
| [015](015-wasm-jsdoc-comments.md) | wasm-jsdoc-comments | ⏳ |
| [016](016-hello-world-examples.md) | hello-world-examples | ⏳ |

## Audience (017–020)

| # | Slug | Status |
|---|---|---|
| [017](017-sinatra-verifier-quickstart.md) | sinatra-verifier-quickstart | ⏳ |
| [018](018-cnml-walkthrough.md) | cnml-walkthrough | ⏳ |
| [019](019-executive-doc.md) | executive-doc | ⏳ |
| [020](020-nist-mpts-harness-bindings.md) | nist-mpts-harness-bindings | ⏳ |

## Topical (021–025)

| # | Slug | Status |
|---|---|---|
| [021](021-pq-signature-verification.md) | pq-signature-verification | ⏳ |
| [022](022-fips-140-mode.md) | fips-140-mode | ⏳ |
| [023](023-test-vector-verification.md) | test-vector-verification | ⏳ |
| [024](024-cnml-certificate-profile.md) | cnml-certificate-profile | ⏳ |
| [025](025-jurisdictional-policy-hooks.md) | jurisdictional-policy-hooks | ⏳ |

## Security (026–031)

| # | Slug | Status |
|---|---|---|
| [026](026-input-size-caps.md) | input-size-caps | ✅ |
| [027](027-dsl-depth-limit.md) | dsl-depth-limit | ⏳ |
| [028](028-zeroize-on-drop.md) | zeroize-on-drop | ⏳ |
| [029](029-cms-signed-attrs-canonicalization.md) | cms-signed-attrs-canonicalization | ⏳ |
| [030](030-consistency-proof-security.md) | consistency-proof-security | ⏳ |
| [031](031-audit-log-exposure.md) | audit-log-exposure | ⏳ |

## Cross-cutting requirements (apply to every TODO above)

Every code change must satisfy:

- **OCP**: new behavior = new file/class; existing classes stay closed
  for modification.
- **DRY**: single source of truth; re-use existing helpers (e.g. one
  canonical P-256 verifier in `confium-composite`, not inlined in pki.rs
  and composite.rs).
- **MECE**: each concern in exactly one module; no overlap.
- **Model-driven**: classes named after domain concepts; methods after
  domain actions.
- **Performance**: target ≤ 2× of native Rust for any wrapping call.
- **Specs**: every public method has ≥ 1 happy-path spec + ≥ 1
  validation spec.
- **Ruby autoload only**: never `require_relative`. Always register
  `autoload :Const, "path/to/file"` in the immediate parent's file
  (create the file if it doesn't exist).
- **No `send` to private methods**: not in spec, not in lib, not in
  benchmarks.
- **No `instance_variable_get` / `instance_variable_set`**: expose
  state via `attr_reader` / `attr_writer` or rethink ownership.
- **No `respond_to?`**: use `is_a?` for type checks, or design the type
  hierarchy so the check isn't needed.
- **Type-safe errors**: typed `Confium::FooError < Confium::Error`, not
  bare `RuntimeError`.

## Sequencing

Suggested order of execution — quick wins first to build momentum,
then security, then functional gaps that unlock downstream work.

1. **Quick wins (≤ 1 PR each)**: 003, 014, 026, 027, 016, 015
2. **Security hardening**: 028, 029, 030 (paired with 010), 031
3. **Architectural foundations**: 001, 002, 005, 004
4. **Verifier completeness**: 008, 012, 013
5. **Issuer completeness**: 006, 007, 024
6. **Threshold + audit**: 009, 010, 011
7. **PQ + compliance**: 021, 022, 023, 025
8. **Audience docs**: 017, 018, 019, 020

Total: 31 items.
