# 027 — DSL depth limit

**Category**: Security
**Severity**: Medium (DoS via stack overflow)
**Effort**: Small (1 PR)

## Problem

`Confium::Attributes.parse` accepts a DSL like
`and(and(and(and(...))))` recursively. A deeply nested input could
overflow the Rust stack and panic the process. The DSL grammar is
unbounded.

## Acceptance criteria

- [ ] A `MAX_DSL_DEPTH = 32` constant in `confium_attributes`.
- [ ] `dsl::parse` tracks recursion depth and returns
     `ParseError::DepthExceeded { depth, max }` if exceeded.
- [ ] The Ruby side raises `Confium::ParseError` with a clear message.
- [ ] Spec: 33 nested `and(and(...))` raises; 32 succeeds (if otherwise
     valid).

## Anti-patterns

- "DSL is small" — an attacker can craft adversarial input.
- Panic on overflow — graceful error is better.

## Approach

In `confirm_attributes::dsl::parse_expr`, count `parse_expr` calls
recursively. Pass a mutable depth counter down. Bump on entry,
decrement on exit. If depth > `MAX_DSL_DEPTH`, return the error.

## Related

- [026-input-size-caps.md](026-input-size-caps.md) — same DoS class
  (different vector).
