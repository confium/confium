# 001 — Typed Ruby error hierarchy

**Category**: Architectural
**Severity**: High (usability + correctness)
**Effort**: Medium (1 PR)

## Problem

Every Rust error currently becomes `RuntimeError` with a Rust-formatted
string. Ruby users cannot `rescue Confium::InvalidSignatureError` or
otherwise dispatch on the failure mode.

Concrete examples from the v0.1.0 surface:

- `Confium::PKI::Certificate.from_der(bad_bytes)` raises `RuntimeError`.
- `Confium::Composite::Signature#verify(msg)` returns a result object
  (good), but a `RuntimeError` is raised for empty components, parse
  errors, etc.
- `Confium::TC::FrostP256.recover_secret(...)` raises `RuntimeError` on
  duplicate x-coordinates.
- `Confium::Attributes.parse(bad_dsl)` raises `RuntimeError`.

## Acceptance criteria

- [ ] `Confium::Error < StandardError` is the root of all Confium errors.
- [ ] At least these subclasses exist, mapped from Rust variants:
  - `Confium::ParseError` — JSON/PEM/DER/DSL parse failures
  - `Confium::ValidationError` — input shape/size wrong
  - `Confium::VerificationError` — signature/hash mismatch
  - `Confium::ThresholdError` — Shamir/threshold violations
  - `Confium::CryptoError` — primitive-level failures (e.g. bad scalar)
  - `Confium::NotFoundError` — slot/cert/share missing
  - `Confium::IndexError` — out-of-range index
- [ ] Every existing `RuntimeError` raise in the binding is replaced
  with the most specific subclass.
- [ ] Each subclass has a `cause` and a structured `details` Hash.
- [ ] Specs cover every error variant at least once.
- [ ] RBS signatures include the error hierarchy.

## Anti-patterns (forbidden in this work)

- `raise "string"` — always raise a typed error.
- `rescue => e` then string-match on `e.message` — use `rescue Confium::FooError`.
- `respond_to?(:code)` to detect error type — use `is_a?`.

## Approach

1. Define the error hierarchy in pure Ruby at `lib/confium/errors.rb`
   (registered as `autoload :Errors, "confium/errors"` in `lib/confium.rb`).
2. Each error class has `attr_reader :details` and accepts
   `initialize(message, details: {})`.
3. The Rust extension maps Rust error variants → Ruby error class names
   via a free function `raise_confium_error(class_name, message, details)`
   called from every binding site.
4. Existing specs updated; new specs added for each variant.

## Related

- [013-structured-error-context.md](013-structured-error-context.md) —
  this is the foundation for structured context.
