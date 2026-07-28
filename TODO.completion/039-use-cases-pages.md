# 039 — `/use-cases/` pages

**Category**: Documentation
**Severity**: High (scenario hub — answers "what's it for?")
**Effort**: Medium (one PR — 6 Markdown files)

## Problem

Readers who skim the homepage and ask "is this for me?" need concrete
scenarios. The plan calls for six use-case pages spanning the three
deployment modes plus PQ migration.

## Acceptance criteria

- [ ] `src/content/use_cases/web-tls.md` — threshold TLS signing via
  the OpenSSL 3.0 provider. Mode 2 angle.
- [ ] `src/content/use_cases/code-signing.md` — multi-stakeholder code
  signing (no single maintainer holds the full key). Mode 2 angle.
- [ ] `src/content/use_cases/distributed-custody.md` — MPC wallets,
  threshold key escrow (Thunderbird-style key backup generalized).
  Mode 1 angle.
- [ ] `src/content/use_cases/sovereign-pki.md` — institutional PKI
  without a single trusted party. Mode 3 angle. CNML appears as one
  of six institutional examples (BIPM calibration, pharma regulator
  approvals, academic accreditation, supply-chain provenance, treaty
  organizations). **No OIML branding.**
- [ ] `src/content/use_cases/pq-migration.md` — HSM-free PQ migration
  via composite signatures. Cross-mode.
- [ ] `src/content/use_cases/supply-chain.md` — provenance tracking
  with transparency logs. Cross-mode.
- [ ] Every page has: problem statement, how Confium solves it, code
  snippet (Ruby preferred — most accessible), link into relevant
  `/docs/` page, "when to choose this" callout.
- [ ] Every page uses Markdown (not AsciiDoc) per the content config.
- [ ] Use cases render via `globLoader` with frontmatter
  `title`, `description`, `mode` (1/2/3/cross), `order`.
- [ ] `/use-cases/index.astro` lists all six, grouped by mode.
- [ ] No "OIML"; no "TODO"/"coming soon".

## Anti-patterns

- Vendor pitches — every claim must trace back to shipped functionality.
- "CNML is the flagship" framing — CNML is *one* example among six in
  the Sovereign PKI page.
- Burying the code snippet below three paragraphs of prose.

## Approach

Single PR. Sovereign PKI page is the heaviest write (Mode 3 rebrand);
others are ~150–250 lines each. Use cases use Markdown per plan
(hand-written, frontmatter-driven) — keep them lighter than the
AsciiDoc docs pages.

## Related

- [036-docs-pages.md](036-docs-pages.md) — mode detail pages these
  link into.
- [035-homepage-vue-islands.md](035-homepage-vue-islands.md) — the
  ModeSelector cards link to these.
