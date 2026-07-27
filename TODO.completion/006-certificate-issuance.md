# 006 — Certificate issuance (build + sign)

**Category**: Functional
**Severity**: High (CNML issuer-side blocker)
**Effort**: Large (multi-PR)

## Problem

`Confium::PKI::Certificate` can parse and inspect but cannot be built
or signed. A CNML issuer (BIML, IA, manufacturer) needs to construct
certificates from scratch and sign them with their CA key.

The Rust crate `confium-pki::cert::builder` is currently private; only
the read-side `Certificate` is exposed.

## Acceptance criteria

- [ ] `Confium::PKI::Certificate::Builder` Ruby class with a fluent API:
  - `Builder.new` → fresh builder
  - `#subject(name:)`, `#issuer(name:)` — RFC 4514 Distinguished Names
  - `#validity(not_before:, not_after:)` — Time or ISO8601 strings
  - `#serial(number)` — Integer or hex String
  - `#public_key(spki_bytes)` — SubjectPublicKeyInfo DER bytes
  - `#extension(oid, value:, critical:)` — add an X.509 extension
  - `#sign(private_key, algorithm:)` → `Certificate`
- [ ] Algorithm dispatch covers Ed25519, ECDSA-P256, ECDSA-P384.
- [ ] Builder is immutable: each method returns a new Builder (current
     state + the change).
- [ ] Spec: build a self-signed root cert, parse it back via
     `Certificate.from_der`, fields match inputs.
- [ ] Spec: build a leaf cert signed by a CA, verify the signature via
     the CA's public key.

## Anti-patterns

- Mutable builder with `self` return — silent state changes.
- `respond_to?(:to_der)` to detect built certs — use `is_a?(Certificate)`.

## Approach

Multi-PR breakdown:

1. **PR 1 (confium-rs)**: make `confium-pki::cert::builder` public.
   Republish `confium-pki` 0.3.1.
2. **PR 2 (Ruby)**: thin wrapper exposing the Builder API above.
3. **PR 3 (specs)**: round-trip specs for self-signed CA + leaf signed
   by CA + extension carry-through.

## Related

- [007-cms-signing.md](007-cms-signing.md) — once certs can be built,
  CMS envelopes can be produced.
- [024-cnml-certificate-profile.md](024-cnml-certificate-profile.md) —
  CNML-specific cert profile uses this Builder.
