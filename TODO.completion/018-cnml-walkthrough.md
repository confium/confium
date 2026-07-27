# 018 — OIML CNML walkthrough

**Category**: Audience
**Severity**: High (flagship use case)
**Effort**: Medium (1 PR — documentation + sample fixtures)

## Problem

CLAUDE.md mentions OIML CNML as the flagship Mode 3 deployment. But
there's no walkthrough of what a CNML certificate workflow actually
looks like with Confium. Decision-makers can't evaluate "is this right
for us?" without one.

## Acceptance criteria

- [ ] `docs/use-cases/cnml/` directory with:
  - `README.md` — overview of CNML + Confium's role
  - `01-issuing-authority-setup.md` — IA generates a root, issues
    manufacturer certs
  - `02-manufacturer-certificate-issuance.md` — manufacturer requests
    a cert, IA signs
  - `03-test-report-signing.md` — testing lab signs a test report
    with threshold TC
  - `04-verification-by-importer.md` — importer (customs) verifies
    the chain
  - `05-transparency-anchoring.md` — IA anchors each issued cert in
    the public log
  - `06-pq-migration.md` — IA migrates to PQ-safe composite sigs
- [ ] Each doc references real code from the integration spec.
- [ ] Sample fixtures (`docs/use-cases/cnml/fixtures/`) include sample
     cert PEMs, manifest TOMLs, and the expected JSON output.

## Anti-patterns

- Hand-waving "and then TC happens" — show the actual Ruby calls.
- Treating OIML R 76 / R 49 etc. as one-size-fits-all — they aren't.

## Approach

Draft each doc against the v0.1.0 + v0.2.0 API surface. Iterate as
features land (cert issuance, CMS signing, etc.).

## Related

- [024-cnml-certificate-profile.md](024-cnml-certificate-profile.md) —
  CNML-specific cert profile implementation backs the walkthrough.
- [019-executive-doc.md](019-executive-doc.md) — higher-level version
  for non-developers.
