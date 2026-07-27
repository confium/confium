# 025 — Jurisdictional policy hooks

**Category**: Topical
**Severity**: Medium
**Effort**: Medium (1 PR)

## Problem

Different jurisdictions require different algorithms / key lengths:
EU doesn't accept <112-bit symmetric; US accepts SHA-1 legacy; China
requires SM2/SM3/SM4 (not currently implemented); Russia's GOST
(not implemented). A confium consumer can't say "this deployment is
EU-compliant" or "this is China-compliant".

## Acceptance criteria

- [ ] `Confium::Jurisdiction` Ruby module:
  - `Jurisdiction::EU` (or `CNML_EU`), `Jurisdiction::CNML_US`,
     `Jurisdiction::CNML_CN`, `Jurisdiction::CNML_RU` constants.
  - Each has a `policy` Hash of allowed algorithms + minimum key sizes.
  - `Confium.jurisdiction = Jurisdiction::CNML_EU` (singleton) applies
     policy to all subsequent cert creation + verification.
  - When a cert violates policy (e.g. RSA-1024 in EU mode),
     verification fails with `Confium::JurisdictionViolationError`.
- [ ] `confium_pki::policy::eu`, `confium_pki::policy::us` etc. Rust
     modules.
- [ ] Spec: EU policy rejects RSA-1024, accepts ECDSA-P256 + RSA-2048+.

## Anti-patterns

- "Enforce FIPS" — too narrow. The hook is more general (any
  jurisdiction's policy).
- "Check NIST-curve compliance" — overlap with CNML profile. Pick one.

## Approach

Policy is a Hash of `{ algorithm_name => minimum_key_bits }`. Each
jurisdiction has a frozen Hash. The verifier + builder consult the
active policy.

## Related

- [022-fips-140-mode.md](022-fips-140-mode.md) — FIPS mode is a
  special case of jurisdictional mode.
- [024-cnml-certificate-profile.md](024-cnml-certificate-profile.md) —
  cert profile plus jurisdictional policy.
