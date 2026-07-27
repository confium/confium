# 002 — DRY: single P-256 verifier

**Category**: Architectural
**Severity**: Medium
**Effort**: Small (1 PR to confium-composite + 2 follow-ups)

## Problem

`p256_verify_inline` is duplicated in:

- `confium-ruby/ext/confium_native/src/pki.rs` (used by CMS verify)
- `confium-ruby/ext/confium_native/src/composite.rs` (used by
  CompositeSignature#verify)

The Rust crate `confium-composite` exports `ed25519_verifier` but not a
P-256 verifier. This violates DRY — three places now have P-256 ECDSA
verification logic.

## Acceptance criteria

- [ ] `confium-composite` Rust crate exports `pub fn p256_verifier(...)`
  alongside `ed25519_verifier`. Mirrors the existing API.
- [ ] `confium-composite` crate version bumped to 0.3.1; republished to
  crates.io.
- [ ] Both Ruby modules call `confium_composite::p256_verifier`; remove
  `p256_verify_inline`.
- [ ] WASM composite.rs also uses the new shared verifier.
- [ ] All existing specs continue to pass.

## Anti-patterns

- Re-implementing crypto verification across modules.
- Vendoring the verifier because "it's small". Use the canonical impl.

## Approach

1. In `confium/crates/confium-composite/src/lib.rs`, add a
   `p256_verifier` function next to `ed25519_verifier` — copy the body
   from the Ruby extension's inline copy.
2. Add `pub const ECDSA_P256: &str = "ECDSA-P256";` constant.
3. Cut release 0.3.1, publish.
4. Update both Ruby extension modules + WASM composite.rs to use the
   shared verifier.

## Related

- [005-composite-verifier-callback.md](005-composite-verifier-callback.md) —
  builds on this by adding a callback surface for unknown algorithms.
