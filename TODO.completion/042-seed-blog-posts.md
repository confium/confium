# 042 — Seed blog posts (3)

**Category**: Documentation
**Severity**: Medium (signals project momentum at launch)
**Effort**: Small (one PR — 3 AsciiDoc files)

## Problem

An empty `/blog/` reads as "this project is dead". Three substantive
launch posts establish voice, anchor the brand (Sovereign PKI), and
give readers something to share.

## Acceptance criteria

- [ ] `src/content/blog/2026-07-28-introducing-confium.adoc` — the
  vision post. Why Confium exists, what threshold-native trust
  infrastructure means, the three modes at a glance, why now (PQ
  pressure, single-key CA incidents). ~1200–1500 words.
- [ ] `src/content/blog/2026-07-28-sovereign-pki-launch.adoc` — Mode 3
  deep dive. The Sovereign PKI brand, what makes it different from
  conventional PKI, the six institutional scenarios (CNML as one
  example), how it maps to the framework. ~1000–1300 words. **No OIML.**
- [ ] `src/content/blog/2026-07-28-pq-migration-walkthrough.adoc` —
  composite signatures end-to-end. The PQ migration problem, why
  software upgrades beat HSM replacement, walk-through of a hybrid
  Ed25519 + ECDSA-P256 + ML-DSA-65 signature, migration timeline
  advice. ~1000–1300 words.
- [ ] Each post has YAML frontmatter: `title`, `description`,
  `author`, `date`, `tags` (array), `category`.
- [ ] `/blog/index.astro` lists posts grouped by year (2026). Reverse
  chronological order.
- [ ] `/blog/[...id].astro` renders single posts via DocsLayout.
- [ ] RSS feed at `/rss.xml` includes all three posts.
- [ ] Every post cross-links to at least one `/docs/` or `/concepts/`
  page.
- [ ] No "OIML"; no "TODO"/"coming soon".

## Anti-patterns

- Marketing fluff — every claim must link to a deeper page.
- "We're excited to announce..." opener — find a stronger hook.
- Burying the code snippet on the PQ migration post — show the actual
  signature flow inline.

## Approach

Single PR. Write in the order above (the introducing post sets the
tone; the other two build on it). Aim for distinctive voice — the
sister RNP blog has a confident, technical voice; match that energy.

## Related

- [036-docs-pages.md](036-docs-pages.md) — the docs pages these posts
  link into.
- [038-concepts-pages.md](038-concepts-pages.md) — the TLS analogy post
  leans on the concepts/threshold-crypto-101 page.
- [035-homepage-vue-islands.md](035-homepage-vue-islands.md) — homepage
  can feature the latest post in a "Latest" section.
