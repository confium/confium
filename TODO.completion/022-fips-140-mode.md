# 022 — FIPS 140 mode

**Category**: Topical
**Severity**: High (US/Canada government deployment blocker)
**Effort**: Very large (multi-PR + external validation)

## Problem

No FIPS 140-validated crypto mode. US federal, Canadian federal, and
many healthcare / finance deployments require FIPS. The Rust workspace
can use Botan (FIPS-validated) via the `hash-botan` plugin but the
binding surfaces don't expose a "FIPS mode" toggle.

## Acceptance criteria

- [ ] `Confium.fips_mode = true` Ruby toggle:
  - When enabled, only FIPS-approved algorithms are available.
  - Non-FIPS algorithms raise `Confium::FipsViolationError`.
  - Internally routes through the Botan plugin (which is
    FIPS-validated).
- [ ] WASM gains no FIPS mode (browsers can't be FIPS-validated).
- [ ] Docs explain: FIPS 140-3 Level 1 vs Level 2 vs Level 3, what
     Confium supports.
- [ ] Spec: in FIPS mode, ECDSA-P256 works; Ed25519 raises.

## Anti-patterns

- Claiming FIPS validation without a real certificate from NIST/CSE.
- "FIPS-compliant" weasel words — either validated or not.

## Approach

This is a multi-year, multi-$ track:

1. **Engineering**: wire the Botan plugin through to Ruby as a backend
   selector. ~3 PRs.
2. **Validation**: contract an accredited lab (atsec, UL) for FIPS 140-3
   testing. Not in scope for code work.
3. **Certificate**: submitted to NIST/CSE. ~12-18 months.

For now: implement the engineering side; document the validation
process as out-of-scope for code.

## Related

- [025-jurisdictional-policy-hooks.md](025-jurisdictional-policy-hooks.md) —
  jurisdictional mode is a generalization of FIPS mode.
