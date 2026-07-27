# 005 — Composite verifier callback surface

**Category**: Architectural
**Severity**: Medium (blocks PQ migration)
**Effort**: Medium (1 PR each for Ruby + WASM)

## Problem

`Confium::Composite::Signature#verify(message)` dispatches by algorithm
string but the dispatch is hardcoded: Ed25519 + ECDSA-P256 only. There
is no way for a Ruby caller to plug in an ML-DSA-65 verifier (or any
custom algorithm).

## Acceptance criteria

- [ ] `Signature#verify(message, verifiers: {})` accepts an optional
     `verifiers:` keyword arg.
- [ ] Each key in `verifiers:` is an algorithm string; each value is a
     `Proc` (Ruby) / `Function` (JS) taking `(public_key_bytes, message,
     signature_bytes) -> bool`.
- [ ] Built-in verifiers (Ed25519 + ECDSA-P256) are still used by
     default for those algorithms.
- [ ] When the composite contains an algorithm with no built-in AND no
     caller-supplied verifier, the result is a per-component failure
     (with a clear "no verifier for X" error), not an exception.
- [ ] Spec: caller supplies a fake "ML-DSA-65" verifier; composite
     verifies successfully using it.
- [ ] WASM `CompositeSignature.verify(message, verifiers)` mirrors this.

## Anti-patterns

- Raising on unknown algorithms — caller-supplied verifier is the
  escape hatch.
- Hardcoding algorithm dispatch in a `match` — register verifiers in a
  HashMap keyed by algorithm.

## Approach

Ruby: pass a Ruby Hash<String, Proc> through magnus. Each invocation
calls the Proc via `magnus::block_call`.

WASM: pass a JS object; wasm-bindgen surfaces it as `JsValue`. Each
invocation calls `.call(publicKey, message, signature)`.

## Related

- [002-dry-p256-verifier.md](002-dry-p256-verifier.md) — pre-req.
- [021-pq-signature-verification.md](021-pq-signature-verification.md) —
  the killer use case for this callback.
