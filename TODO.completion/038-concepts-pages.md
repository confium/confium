# 038 — `/concepts/` pages

**Category**: Documentation
**Severity**: High (educational hub — gateway for non-expert readers)
**Effort**: Medium (one PR — 5 AsciiDoc files)

## Problem

`/docs/` speaks to engineers who already know what threshold crypto is.
`/concepts/` is the educational on-ramp: an executive or junior dev
lands here first to build a mental model before tackling the docs.
Without these pages, the site reads as insider-only.

## Acceptance criteria

- [ ] `src/content/concepts/threshold-crypto-101.adoc` — T-of-N
  intuition, Shamir secret sharing explained from first principles,
  Lagrange interpolation (light touch), why T-of-N beats single-key.
  Includes a worked example: "3-of-5 directors required to sign".
- [ ] `src/content/concepts/tls-analogy.adoc` — the central analogy:
  *"Confium is to threshold cryptography what TLS libraries are to
  transport security — a configurable framework organizations deploy
  with their own parameters."* Explains the analogy in both directions
  (what Confium provides vs. what plugins provide).
- [ ] `src/content/concepts/composite-signatures.adoc` — why hybrid
  PQ/classical signatures matter, how Confium composes them, migration
  path without re-issuing every certificate.
- [ ] `src/content/concepts/transparency-logs.adoc` — RFC 6962 primer:
  Merkle trees, inclusion proofs, consistency proofs, split-view
  attacks, witness gossip, OTS anchoring. Lighter than the docs page —
  intuition first, math second.
- [ ] `src/content/concepts/attribute-based-threshold.adoc` —
  predicates, the DSL, "5-of-9 directors from 3 distinct regions",
  why attribute-based beats fixed-quorum.
- [ ] Every page cross-links to the deepest `/docs/` page that uses
  the concept and to relevant `/glossary/` anchors.
- [ ] Every page renders correctly through the custom `adocLoader`.
- [ ] No "OIML"; no "TODO"/"coming soon"/"planned".

## Anti-patterns

- Duplicating the docs page content — concepts give *intuition*, docs
  give *normative detail*. They link to each other, not overlap.
- Academic tone — concepts should read like a smart blog post, not a
  textbook chapter.
- Skipping diagrams — at least one inline SVG or ASCII diagram per
  concept page where it aids understanding.

## Approach

Single PR. Write in the order above (101 first as it sets vocabulary).
Each page: 200–400 lines, AsciiDoc, 1–2 diagrams, 2–3 code snippets max.
The TLS analogy page is the most important — it's the homepage subtitle
expanded.

## Related

- [036-docs-pages.md](036-docs-pages.md) — the deeper pages these
  concepts link into.
- [040-glossary-page.md](040-glossary-page.md) — term definitions.
- [042-seed-blog-posts.md](042-seed-blog-posts.md) — the "Introducing
  Confium" post will lean on the TLS analogy.
