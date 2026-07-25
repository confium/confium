# 15 — Documentation, specs, GitHub issue management

## Why

Closing the loop on the GitHub issue backlog (#1, #3, #4, #7, #11, #12,
#13) and keeping CLAUDE.md / README.adoc / CHANGELOG.md in sync with
the implementation.

## Acceptance checklist

### GitHub issues

- **#3** (FFI error handling): close with reference to the
  `cfm_err_get_source` implementation from TODO #03.
- **#4** (Sensitive and Secret): close the `Sensitive` portion with
  reference to TODO #13 implementation. Open a follow-up issue for
  `Secret` (encrypted-at-rest memory) labeled `phase-2`.
- **#7** (Document how to run tests): close. `CONTRIBUTING.md` (added
  in the modernization PR) covers this.
- **#13** (RSA for Botan plugin): comment that the issue belongs in
  the `github.com/confium/hash-botan` (or `confium-botan`) repo now,
  and close it here. The `cfm_sig_*` interface from TODO #09 lands
  the framework; the actual Botan RSA implementation is the plugin's
  responsibility.
- **#1** (Phase 1 PoC): comment with status:
  - Plugin structure, hash interface, CI, cross-platform release:
    **done** in 0.2.0
  - RSA primitive support: framework lands in TODO #09; algorithm in
    Botan plugin
  - Interoperable key format: lands as TODO #11 (keyfmt)
  - Mock module repository: split into new issue, not in 0.x roadmap
- **#11** (Phase 2 keystore): the framework lands as TODO #12.
  Persistence format, file backend, etc. tracked as sub-issues.
- **#12** (Phase 3 threshold): leave open as future research. Out of
  scope for any 0.x release.

### CLAUDE.md

- Update architecture section to mention the new plugin registry
  pattern (TODO #02).
- Document the interfaces Confium exposes: hash, cipher, aead, kdf,
  rng, signature, kem, keyfmt, keystore (each as a section).
- Mention `Sensitive<T>` (TODO #13) and where it's used.

### README.adoc

- "Build steps" section: no changes (still `cargo build`).
- "Tests" section: add Rust unit tests for new interfaces.
- "Algorithms supported" section: new — list the algorithm matrix
  derived from TODO #01. Note that the framework supports all; each
  plugin implements a subset.

### CHANGELOG.md

One entry per TODO under `[0.3.0] — Unreleased` (or appropriate bump):

```markdown
## [0.3.0] — Unreleased

### Added

- Plugin interface registry (open/closed-compliant): new interface
  types can be added in their own module with zero edits to existing
  code.
- `cfm_err_get_source` walks the snafu error chain across the FFI.
  Closes #3.
- New crypto interfaces: `symmetric`, `aead`, `kdf`, `rng`,
  `signature`, `kem`, `keyfmt`, `keystore`.
- `Sensitive<T>`: zeroize-on-drop wrapper for confidential data.

### Changed

- Each plugin interface module registers itself with the global
  registry at link time. No more central enum.
- All `*mut FFIHash`-style opaque handles now use a shared
  `OpaqueHandle` type where the underlying plugin type isn't
  meaningfully distinct (e.g. RNG state vs hash state are both
  opaque).
```

### Specs

Every new interface module ships with at least:

- One unit test exercising the Rust wrapper API end-to-end with a
  mock plugin.
- One doctest on the public function.
- Round-trip tests (create → use → destroy) to catch leaks (run under
  valgrind in CI optionally).

For `src/ffi/error.rs`: tests covering `cfm_err_get_source` for every
`Error` variant with and without a source field.

## Files touched

- Edit: `CLAUDE.md`
- Edit: `confium/README.adoc`
- Edit: `confium/CHANGELOG.md`
- GitHub issue comments / closes

## Dependency

- After TODOs #02 through #13 land so we know what to document.
- Can partially run in parallel — close #7 and #3 as soon as those
  TODOs complete, even before the larger interfaces land.
