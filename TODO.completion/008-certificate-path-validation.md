# 008 — Certificate path validation

**Category**: Functional
**Severity**: High (verifier-side blocker)
**Effort**: Medium (1 PR)

## Problem

`confium-pki::path::validate_path` exists in Rust, validates a cert
chain against a trust anchor. The Ruby gem doesn't expose it. A
verifier consumer can't validate that a leaf cert chains to a trusted
root through valid intermediates.

## Acceptance criteria

- [ ] `Confium::PKI::PathValidator` Ruby class:
  - `.validate(leaf:, intermediates:, root:, now: Time.now)` →
    `Confium::PKI::PathValidationResult`
- [ ] Result exposes `#valid?`, `#errors` (Array<String>),
     `#checks` (Array<String>).
- [ ] Validates: signature chain, time validity at `now`, basic
     constraints, key usage extensions.
- [ ] Spec: 3-cert chain (root → intermediate → leaf), all valid →
     `valid? == true`.
- [ ] Spec: expired leaf → `valid? == false`, `errors` mentions
     `expired`.
- [ ] Spec: signature from wrong issuer → `valid? == false`, `errors`
     mentions `signature`.
- [ ] WASM equivalent (`PathValidator.validate(...)`) — read-only,
     useful for browser-side verifier.

## Anti-patterns

- "Just check the leaf's signature against its issuer" — that's not
  path validation.
- Treating trust-root discovery as caller's problem — provide a sane
  default.

## Approach

1. Wire `validate_path` through to Ruby via magnus.
2. The wrapper takes Ruby `Certificate` instances and adapts them to
   `confium_pki::path::CertPath`.
3. Spec fixtures: 3 openssl-generated certs chained root → intermediate
   → leaf.

## Related

- [006-certificate-issuance.md](006-certificate-issuance.md) — produces
  the certs that this validates.
- [017-sinatra-verifier-quickstart.md](017-sinatra-verifier-quickstart.md) —
  this is the centerpiece of the verifier-side quickstart.
