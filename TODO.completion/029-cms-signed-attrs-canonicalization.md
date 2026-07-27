# 029 — CMS signedAttrs canonicalization

**Category**: Security
**Severity**: High (signature forgery / replay)
**Effort**: Medium (1 PR)

## Problem

`Confium::PKI::CMS::SignedData#verify_signatures` (added in PR #27)
computes the signed bytes from `encap_content_info.content`. But CMS
signatures are typically over `signed_attrs` (RFC 5652 §5.3) re-encoded
in DER canonical form. If the Ruby verify path doesn't enforce that
the signed attrs are DER-canonical, a malicious envelope could swap
them out without breaking verification.

## Acceptance criteria

- [ ] `confium_pki::cms::canonical_signed_attrs(attrs) -> Vec<u8>`
     computes the DER-canonical encoding of `Set<Attribute>`.
- [ ] `verify_signed_data` uses this canonical encoding as the signed
     bytes when `signed_attrs` is present (overriding `content`).
- [ ] If `signed_attrs` is present but the verifier's recomputed
     canonical encoding differs from what the signer_info claims was
     signed, the signer fails verification with `Confium::VerificationError`.
- [ ] Spec: a malicious envelope with two encodings of the same
     `signed_attrs` (canonical + DER-reencoded) — canonical verifies,
     reencoded fails.

## Anti-patterns

- "Trust the bytes from the wire" — that's what an attacker sends.
- "Just compare hash of attrs" — hash collisions are an attack vector.

## Approach

1. Implement `canonical_signed_attrs` in `confium_pki::cms::verify`.
2. Update `verify_signed_data` to compute canonical bytes when
   `signed_attrs` is non-empty.
3. Update the Ruby extension to surface the typed error.

## Related

- [004-cms-per-signer-resolution.md](004-cms-per-signer-resolution.md) —
  per-signer cert resolution is the other half of CMS verify.
- [007-cms-signing.md](007-cms-signing.md) — signing side must produce
  canonical attrs too.
