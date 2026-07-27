# 019 — Executive doc (for CIO/CTO-level decision-makers)

**Category**: Audience
**Severity**: Medium
**Effort**: Small (1 PR — documentation)

## Problem

All existing docs are for developers. Decision-makers (CIO, CTO,
compliance officer, security architect) need a different doc: not "how
to call the API" but "why this, not OpenSSL / a vendor HSM / nothing".

## Acceptance criteria

- [ ] `docs/executive/why-confium.md` covers:
  - **The problem**: PKI's single-point-of-failure trust model.
  - **The cost of the status quo**: CA breaches, key compromise, vendor
    lock-in.
  - **What Confium changes**: threshold-by-default, no single party can
    sign, open-source, multi-stakeholder governance.
  - **Compliance hooks**: FIPS 140 mode ([022](022-fips-140-mode.md)),
    jurisdictional policies ([025](025-jurisdictional-policy-hooks.md)).
  - **Operational impact**: who staffs what, what changes for existing
    PKI consumers.
  - **Cost model**: open-source licensing, no per-transaction fees.
  - **Migration path**: hybrid composite-signature mode for PQ
    migration without breaking existing verifiers.
- [ ] No code snippets — execs don't read code.
- [ ] Diagrams where applicable (PowerPoint-grade, notPlantUML — execs
     don't render).
- [ ] Comparison table: Confium vs OpenSSL + in-house HSM vscommercial
     threshold PKI vendor.

## Anti-patterns

- Listing every feature — execs don't care.
- "Disruptive" / "revolutionary" marketing copy.
- Comparing to specific commercial vendors by name.

## Approach

2-3 pages of prose, one comparison table, one migration-phase
diagram. Anchor every claim in a concrete existing deployment pattern
(CNML, BIML, NIST MPTS).

## Related

- [018-cnml-walkthrough.md](018-cnml-walkthrough.md) — concrete use
  case to point at.
