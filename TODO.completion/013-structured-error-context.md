# 013 — Structured error context

**Category**: Usability
**Severity**: Medium
**Effort**: Medium (1 PR; depends on 001)

## Problem

Current Ruby error messages are Rust-formatted strings:

```
RuntimeError: byte out of range 0..255: 999
RuntimeError: invalid composite signature JSON: expected ident at 2:3
RuntimeError: verify: bad signature
```

Users can't programmatically extract context like "which byte index?",
"which signer?", "what was the algorithm?". They have to regex the
message.

## Acceptance criteria

- [ ] Every `Confium::*Error` accepts `details:` keyword.
- [ ] Details Hash includes at least:
  - `:operation` — Ruby method name (e.g. `:from_der`)
  - `:component` — Ruby class/module name (e.g. `"Confium::PKI::Certificate"`)
  - domain-specific fields (see below)
- [ ] `#message` includes the human-readable text + a `[details: ...]`
     suffix for visibility.
- [ ] `#to_h` returns the structured payload.

Per-error domain fields:

| Error | Fields |
|---|---|
| `ValidationError` | `:param`, `:expected`, `:actual` |
| `ParseError` | `:format`, `:offset`, `:line`, `:column` |
| `VerificationError` | `:signer_index`, `:algorithm`, `:reason` |
| `ThresholdError` | `:have_count`, `:need_count` |
| `NotFoundError` | `:kind`, `:identifier` |
| `IndexError` | `:index`, `:valid_range` |

## Anti-patterns

- Embedding context into `message` as English text only — keep
  structured.
- Using a single `details` Hash with no shape per-error-class.

## Approach

Depends on [001-typed-error-hierarchy.md](001-typed-error-hierarchy.md).

Each typed error class declares its details shape via a class-level
method. The Rust side raises with `details` set; the Ruby class
constructor enforces required keys.

## Related

- [001-typed-error-hierarchy.md](001-typed-error-hierarchy.md) — pre-req.
