# 024 — CNML certificate profile

**Category**: Topical
**Severity**: High (flagship domain compliance)
**Effort**: Large (multi-PR + OIML collaboration)

## Problem

OIML R 76 (CNML) specifies required + optional certificate extensions
for measuring instruments. A confium-issued CNML cert needs those
extensions. There's no implementation of the profile.

## Acceptance criteria

- [ ] `confium_pki::profile::cnml` module with:
  - `CnmlProfile::required_extensions()` → list of OIDs
  - `CnmlProfile::validate(certificate, now)` → `Result<(), ProfileError>`
  - `CnmlBuilder::new` → builder pre-populated with the required CNML
     extension OIDs
- [ ] `Confium::PKI::CNML` Ruby module exposes the above.
- [ ] Spec: a CNML-shaped cert validates; a non-CNML cert fails.
- [ ] Spec: a CNML cert with the wrong OID version fails.

## Anti-patterns

- Inventing an OIML "interpretation" — cite the actual OIML R 76
  text.
- Hardcoding the OID list — read from a versioned profile document.

## Approach

1. Read OIML R 76 §6 (or whatever the certificate profile is in the
   current revision).
2. Translate the required extensions + their syntax into Rust types
   in `confium_pki::profile::cnml`.
3. Surface through the Ruby binding.

This requires access to the OIML R 76 PDF (paid publication) — request
via the partnership channel.

## Related

- [006-certificate-issuance.md](006-certificate-issuance.md) — uses
  this profile.
- [018-cnml-walkthrough.md](018-cnml-walkthrough.md) — references the
  profile.
