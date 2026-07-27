# 026 — Input size caps

**Category**: Security
**Severity**: High (DoS vector)
**Effort**: Small (1 PR)

## Problem

`Confium::TC::FrostP256.split_secret(secret, t, n)` etc. accept a
`secret` of arbitrary size. `bytes_from_value` accepts a String OR an
`Array<Integer>`. A `String.new("\x00" * 1_000_000_000)` or
`Array.new(1_000_000_000) { 0 }` would allocate 1GB before the
length validation runs.

The same issue exists for any API that accepts a String of bytes:
`Certificate.from_der`, `CompositeSignature.from_json`, etc.

## Acceptance criteria

- [ ] A single constant `Confium::MAX_INPUT_SIZE = 1 << 20` (1 MiB)
     in pure Ruby.
- [ ] Every `bytes_from_value` Rust call checks the length after
     decoding and raises `Confium::ValidationError` if it exceeds
     `MAX_INPUT_SIZE`.
- [ ] Each public method that takes a byte-string parameter documents
     the size cap and raises cleanly when exceeded.
- [ ] Spec: passing a 2 MiB string to `Certificate.from_der` raises
     `ValidationError` with a clear message.
- [ ] Spec: a normal-size input (under 1 MiB) is unaffected.

## Anti-patterns

- Allocating first, validating later — DoS.
- Hardcoding sizes in each call site — single source of truth.

## Approach

Centralize the size check in the Rust `bytes_from_value` function. Add
a `Confium::MAX_INPUT_SIZE` constant in `lib/confium/constants.rb`
(autoloaded from `lib/confium.rb`). Expose both via magnus so the
Rust side can read the limit at runtime.

Actually simpler: hardcode the limit in Rust (1 MiB), since it's
already a security control. The Ruby side documents it.

## Related

- [027-dsl-depth-limit.md](027-dsl-depth-limit.md) — similar DoS
  protection for the attributes DSL.
- [028-zeroize-on-drop.md](028-zeroize-on-drop.md) — covers the
  allocation-then-zero path.
