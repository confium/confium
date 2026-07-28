# 037 — About + 404 + meta pages

**Category**: Documentation
**Severity**: Medium (table-stakes pages, low complexity)
**Effort**: Small (one PR — 5 simple pages)

## Problem

Every site needs the meta pages: about, 404, contribute, security
disclosure, funding. They're low-effort but high-trust — a missing
`/security/` page reads as "this project doesn't take disclosure
seriously".

## Acceptance criteria

- [ ] `src/pages/about.astro` — governance model (BSD-2-Clause),
  contributor ladder, funding (NLnet NGI Zero PET, Mozilla MOSS),
  contributing pointers, who's behind Confium. Replaces existing
  `about.markdown`. **No OIML.**
- [ ] `src/pages/404.astro` — on-brand 404 with a quorum-themed joke
  ("3 of 5 pages could not be found") + link back to homepage and docs.
- [ ] `src/pages/contribute.astro` — how to contribute: open an issue,
  open a PR, the BSD-2-Clause contributor ladder, code of conduct link,
  good-first-issue pointer.
- [ ] `src/pages/security.astro` — security disclosure policy: how to
  report a vulnerability, PGP key, SLA for response, scope (in-scope vs
  out-of-scope), disclosure timeline commitments.
- [ ] `src/pages/funding.astro` — NLnet NGI Zero PET + Mozilla MOSS
  funding acknowledgements, what each grant covers, link to funders'
  pages.
- [ ] Every page uses `BaseLayout.astro` (not DocsLayout — these are
  full-bleed, not three-column).
- [ ] Mobile-responsive; dark mode clean.
- [ ] No "OIML"; no "TODO"/"coming soon"/"planned".

## Anti-patterns

- Generic 404 ("page not found") — make it on-brand.
- Boilerplate security page that doesn't list a PGP key or SLA —
  reviewers will spot it instantly.
- Burying the license — BSD-2-Clause must appear on About.

## Approach

Single PR, parallel writes possible. About + 404 are the two non-trivial
writes; the other three are mostly structural. Total: ~250 lines across
5 files.

## Related

- [034-astro-site-scaffolding.md](034-astro-site-scaffolding.md) —
  provides the layouts these pages use.
- [042-seed-blog-posts.md](042-seed-blog-posts.md) — the "Introducing
  Confium" post can be cross-linked from About.
