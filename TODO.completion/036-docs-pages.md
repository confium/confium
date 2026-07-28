# 036 — `/docs/` pages

**Category**: Documentation
**Severity**: High (primary technical content surface)
**Effort**: Medium (one PR — 10 AsciiDoc files)

## Problem

After the homepage, `/docs/` is where every technical reader lands.
The plan calls for 10 hand-written `.adoc` pages covering architecture,
the three modes, components, security model, PQ migration, transparency
logs, and getting started.

## Acceptance criteria

- [ ] `src/content/docs/architecture.adoc` — system overview, plugin
  loader, registry, the 10 shipped interfaces, FFI entry points.
  Adapted from `specs/specs/00-framework-overview.adoc` (light edit).
- [ ] `src/content/docs/three-modes.adoc` — Peer-to-Peer TC, PKI
  Drop-in, Sovereign PKI overview. Adapted from
  `specs/specs/01-three-modes.adoc` (OIML stripped, Sovereign PKI
  branded).
- [ ] `src/content/docs/mode1-peer-tc.adoc` — Mode 1 detail. Adapted
  from `specs/specs/10-mode1-peer-tc.adoc`.
- [ ] `src/content/docs/mode2-pki-drop-in.adoc` — Mode 2 detail +
  composite signatures PQ argument. Adapted from
  `specs/specs/11-mode2-pki-replacement.adoc`.
- [ ] `src/content/docs/mode3-sovereign-pki.adoc` — Mode 3 detail,
  branded "Sovereign PKI". **Heavy edit** of
  `specs/specs/12-mode3-certificate-pki.adoc`: strip all OIML
  references, genericize examples (CNML, BIPM calibration, accreditation,
  supply-chain provenance, treaty orgs).
- [ ] `src/content/docs/components.adoc` — 43-crate workspace map by
  category. Fresh write.
- [ ] `src/content/docs/security-model.adoc` — threat model, defense in
  depth. Adapted from `specs/specs/90-security-model.adoc`.
- [ ] `src/content/docs/pq-migration.adoc` — composite signatures deep
  dive, migration path. Synthesizes
  `confium-ruby/docs/pq-migration/composite-signatures.adoc`.
- [ ] `src/content/docs/transparency-logs.adoc` — RFC 6962, inclusion
  proofs, consistency proofs, OTS anchoring, witness gossip. Synthesizes
  `specs/specs/42-transparency-log.adoc` +
  `confium/docs/security/transparency-logs.md`.
- [ ] `src/content/docs/getting-started.adoc` — quickstart hub linking
  into `/software/rust/docs/installation/`,
  `/software/ruby/docs/installation/`, the WASM verifier quickstart.
- [ ] Every page is AsciiDoc with `= Title` H1 + `:toc:` macro.
- [ ] Every page cross-links to at least one sibling doc and one
  `/concepts/` page where applicable.
- [ ] Renders correctly through the custom `adocLoader` (YAML frontmatter
  + AsciiDoc body, h2/h3 TOC extracted).
- [ ] No "OIML"; no "TODO"/"coming soon"/"planned"/"roadmap".

## Anti-patterns

- Copying specs verbatim — the docs pages are *oriented* (audience-aware)
  while specs are normative. Light edit, not dump.
- Inlining SVG diagrams as base64 — place under `public/assets/` and
  reference by path.
- burying the mode-3 Sovereign PKI rebrand — Mode 3 must read as
  Sovereign PKI consistently across homepage, docs, use cases, blog.

## Approach

Single PR. Work through pages in the order listed above (architecture
first as it sets vocabulary). For each spec-derived page, lift the
canonical sections, strip OIML, rebrand mode 3, genericize examples.
Cross-link audit happens at the end of the PR before merge.

## Related

- [038-concepts-pages.md](038-concepts-pages.md) — pages this docs set
  cross-links into.
- [039-use-cases-pages.md](039-use-cases-pages.md) — pages this docs set
  cross-links into.
- [040-glossary-page.md](040-glossary-page.md) — term definitions.
