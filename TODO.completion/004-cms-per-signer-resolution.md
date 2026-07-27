# 004 — CMS per-signer certificate resolution

**Category**: Architectural / Security
**Severity**: High
**Effort**: Medium (1 PR)

## Problem

`Confium::PKI::CMS::SignedData#verify_signatures` uses the **first**
certificate in the `certificates` array for **every** signer. This is
wrong in any real CNML envelope with multiple signers — and a security
hole: a malicious envelope can claim verification by attaching one
valid cert + multiple signer_infos with signatures produced by
different keys.

Worse: the current code uses the first signer_info's
`signature_algorithm` OID for ALL signers. If signer 1 is Ed25519 and
signer 2 is ECDSA-P256, the verifier dispatches both as Ed25519,
producing a misleading error rather than a correct verification.

## Acceptance criteria

- [ ] For each `signer_info`, resolve the signing cert via:
  1. If `sid` is `SubjectKeyIdentifier`, match the SKI extension in
     each cert.
  2. If `sid` is `IssuerAndSerialNumber`, match issuer + serialNumber.
- [ ] Per-signer `signature_algorithm.oid` dispatch (not first OID for
     all).
- [ ] Unresolved signer raises `Confium::UnresolvedSignerError` with
     the signer index in `details`.
- [ ] Spec: a CMS envelope with 2 signers, 2 distinct certs, 2
     distinct algorithms — both must verify correctly.
- [ ] Spec: a malicious envelope with mismatched cert/signer_info
     fails with `Confium::UnresolvedSignerError`.

## Anti-patterns

- "Use the first cert for everything" — security hole.
- "Use the first signer_info's algorithm for everything" — produces
  wrong errors silently.
- `rescue ; nil` to swallow unresolved-signer errors — surface them.

## Approach

1. Add `confium-pki::cert` helpers:
   - `Certificate::subject_key_identifier() -> Option<Vec<u8>>`
   - `Certificate::issuer() -> &[u8]` (DER-encoded Name)
   - `Certificate::serial_number() -> &[u8]`
2. Add `confium-pki::cms::resolve_signer_certificate(signer_info, certs)`
   returning `Result<&[u8], UnresolvedSignerError>`.
3. The Ruby `verify_signatures` calls the resolver per-signer, dispatches
   per-algorithm.

## Related

- [029-cms-signed-attrs-canonicalization.md](029-cms-signed-attrs-canonicalization.md)
  — even with correct cert resolution, signed attrs must be canonical.
