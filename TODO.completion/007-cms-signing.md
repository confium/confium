# 007 — CMS signing

**Category**: Functional
**Severity**: High (issuer-side)
**Effort**: Large (multi-PR)

## Problem

The Ruby gem added `CMS::SignedData#verify_signatures` in PR #27, but
there's no way to *produce* a SignedData. A CNML issuer needs to wrap
a payload in CMS SignedData, sign it, attach the signing cert, and
serialize to JSON or DER.

The Rust crate has `confium-pki::cms::build_detached_signature` but
it's not exposed.

## Acceptance criteria

- [ ] `Confium::PKI::CMS::SignedData::Builder` Ruby class:
  - `Builder.new(content_type: "1.2.840.113549.1.7.1")`
  - `#content(bytes_or_nil)` — attached or detached
  - `#add_certificate(cert_der_bytes)`
  - `#add_signer(cert_der_bytes, private_key_bytes, algorithm:, signed_attrs: {})`
  - `#build` → `SignedData`
- [ ] Algorithm dispatch: Ed25519, ECDSA-P256, ECDSA-P384.
- [ ] Signed attrs include `contentType`, `signingTime`,
     `messageDigest` (computed over content via the digest algorithm).
- [ ] Spec: build → serialize to JSON → parse back → verify round-trips.
- [ ] Spec: detached signature (content=nil) works end-to-end.
- [ ] Spec: 2 signers from 2 different CAs, both verify.

## Anti-patterns

- Allowing caller-supplied `signature_bytes` instead of computing
  signature internally — invites signature-stripping attacks.
- Mutating signer_infos after build — SignedData should be immutable.

## Approach

Multi-PR:

1. **PR 1 (confium-rs)**: expose `cms::envelope::SignedDataBuilder` and
   `build_detached_signature` as public.
2. **PR 2 (Ruby)**: thin wrapper via magnus.
3. **PR 3 (specs)**: round-trip + multi-signer + detached specs.

## Related

- [006-certificate-issuance.md](006-certificate-issuance.md) — pre-req
  (build certs before signing them into CMS).
- [004-cms-per-signer-resolution.md](004-cms-per-signer-resolution.md) —
  the verify side of this.
