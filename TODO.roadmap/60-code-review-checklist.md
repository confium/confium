# 60 — Code review checklist

## Philosophy

Code review at Confium serves three purposes:

1. **Catch bugs** before they ship
2. **Spread knowledge** across the team
3. **Maintain architectural integrity** (OCP, MECE, DRY)

## Reviewer checklist

### Architecture

- [ ] Does the change respect existing module boundaries?
- [ ] If adding a new crate: was the consolidation analysis applied? (see `TODO.roadmap/26`)
- [ ] If adding a new interface: does it use the `register_interface!` pattern?
- [ ] If adding a new algorithm: is it in its own crate with proper deps?
- [ ] Does the change follow OCP (open for extension, closed for modification)?
- [ ] Are new trait additions preferred over new enum arms where future expansion is likely?

### API design

- [ ] Public API documented with `///` doc comments?
- [ ] Function names describe what, not how?
- [ ] Types are domain-meaningful (not generic like `Vec<u8>`)?
- [ ] Error variants are exhaustive and named after failure modes?
- [ ] Builder pattern used for multi-field constructors?
- [ ] No `unwrap()` / `expect()` / `panic!()` in production code paths?

### Cryptography (if crypto-related)

- [ ] Uses established crates (`p256`, `ed25519-dalek`, `aes-gcm`, `sha2`, `ring`)?
- [ ] RNG via `rand_core::OsRng` or Confium's `rng` interface?
- [ ] Constant-time comparisons for secrets (no `==` on `Vec<u8>` containing keys)?
- [ ] Secret-bearing types implement `ZeroizeOnDrop`?
- [ ] No printing/logging of secret bytes (even in debug)?
- [ ] No new `unsafe` blocks added?

### Performance

- [ ] No unnecessary allocations in hot paths?
- [ ] No blocking I/O in async functions (use `spawn_blocking`)?
- [ ] No silent O(n²) algorithms where O(n) is achievable?
- [ ] Caches invalidated correctly when underlying data changes?

### Error handling

- [ ] All fallible operations return `Result`?
- [ ] Errors are typed (thiserror or snafu), not string?
- [ ] Error context preserved (not swallowed by `map_err(|_| ...)`)?
- [ ] No "should never happen" comments without justification?

### Tests

- [ ] New code has unit tests?
- [ ] Edge cases tested (empty, max-size, invalid input)?
- [ ] Round-trip tests for serialization?
- [ ] Threshold-property tests for crypto (different share subsets recover same secret)?
- [ ] No `#[ignore]` tests left without a justification comment?

### Documentation

- [ ] Crate-level `//!` doc comment explains the crate's purpose?
- [ ] Module-level `//!` doc comments explain what's in the module?
- [ ] Public items have `///` doc comments?
- [ ] Doc examples are runnable (`cargo test --doc`)?

### Style

- [ ] `cargo fmt --check` clean?
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean?
- [ ] `cargo machete` no unused dependencies?
- [ ] `typos` clean?

### Security

- [ ] No new dependencies without license/advisory check (cargo-deny)?
- [ ] No `unsafe` without `// SAFETY:` justification?
- [ ] No secret material in error messages, logs, or debug output?
- [ ] Input validation at trust boundaries (FFI, network, file parsing)?
- [ ] No path traversal vulnerabilities in file operations?

### Conventional commits

- [ ] Commit message follows conventional format (`feat:`, `fix:`, `docs:`, etc.)?
- [ ] Breaking changes marked with `!` and explained in body?
- [ ] No AI attribution trailers?
- [ ] PR description explains the "why", not just the "what"?

## Reviewer etiquette

- **Be kind**: critique the code, not the author
- **Be specific**: cite line numbers; suggest concrete fixes
- **Be timely**: review within 24 hours when possible
- **Distinguish blocking from non-blocking**: "must fix" vs "nit"
- **Approve when satisfied**: don't make authors wait unnecessarily

## Author etiquette

- **Self-review first**: read your own diff before requesting review
- **Small PRs**: <500 lines preferred; split large changes
- **One concern per PR**: don't mix features and refactors
- **Respond to all comments**: address or push back; don't ignore
- **Don't take it personally**: review is about the code

## Anti-goals

- **Not** requiring unanimous approval (1 reviewer sufficient for most PRs)
- **Not** bikeshedding style (clippy + fmt enforce style)
- **Not** blocking on minor suggestions

## References

- `TODO.roadmap/42-testing-strategy.md`
- `TODO.roadmap/48-security-audit-checklist.md`
- `TODO.roadmap/26-confium-framework.md` (architecture principles)
