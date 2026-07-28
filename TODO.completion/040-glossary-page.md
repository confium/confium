# 040 — Glossary A–Z page

**Category**: Documentation
**Severity**: Medium (reference surface; high SEO value)
**Effort**: Small (one PR — single page, ~30 entries)

## Problem

Threshold crypto + PKI + transparency log terminology is dense.
Readers need a single A–Z reference they can Cmd+F into. The glossary
also serves as the link target for term-first-mention across all other
pages.

## Acceptance criteria

- [ ] `src/content/glossary/*.md` — one file per term (so the
  `globLoader` picks them up), OR a single `glossary.md` with anchors.
  Recommend single-page with anchor IDs for SEO and search.
- [ ] `src/pages/glossary/index.astro` — single-page A–Z render. No
  per-entry routes (would bloat the URL space for no value).
- [ ] ~30 terms covered (from the plan): threshold cryptography,
  quorum, share, Shamir secret sharing, Lagrange interpolation, FROST,
  CMP20, GG18, re-sharing, Herzberg refresh, coordinator,
  transparency log, Merkle tree, RFC 6962, inclusion proof,
  consistency proof, OpenTimestamps (OTS), composite signature,
  attribute-based threshold signing, PKCS#11, OpenSSL provider,
  JCE provider, CMS, XMLDSig, canonical XML, **Sovereign PKI**,
  deployment manifest, director, ceremony, MPC, ElGamal encryption,
  ECIES.
- [ ] Each entry: 2–4 sentences, plain language, with at least one
  cross-link to the deepest page that uses the term (concept, doc, or
  use case).
- [ ] Alpha-jump nav at top (A B C D … Z) — anchors to the first
  entry of each letter.
- [ ] Searchable via Pagefind (Cmd+K returns the glossary entry as a
  top result for any term).
- [ ] No "OIML"; no "TODO"/"coming soon".

## Anti-patterns

- Wikipedia-style long-form definitions — 2–4 sentences, link out for
  depth.
- Defining "Sovereign PKI" without using the term — Mode 3 IS Sovereign
  PKI on this site.
- Forgetting to add `data-pagefind-body` to the glossary page — must
  be indexed.

## Approach

Single PR. Write all 30 entries in one pass, then alphabetize, then
add cross-links. Verify Pagefind indexes each entry separately by
searching for 3–4 terms after a production build.

## Related

- [036-docs-pages.md](036-docs-pages.md), [038-concepts-pages.md](038-concepts-pages.md)
  — these pages link into glossary anchors.
- [043-search-cross-link-audit.md](043-search-cross-link-audit.md) —
  verifies the glossary is indexed.
