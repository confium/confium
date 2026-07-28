# 041 — Software bindings + specs pull-through

**Category**: Documentation
**Severity**: High (per-repo docs become visible at last)
**Effort**: Medium (one PR — collection metadata + route handlers)

## Problem

TODOs 032 and 033 create `confium/docs/` and `confium-ruby/docs/`. This
TODO wires them into the central Astro site via the `fetch-sources.mjs`
sparse-checkout mechanism established in TODO 034. Without this,
`www.confium.org/software/rust/docs/` and `/software/ruby/docs/` return
404.

## Acceptance criteria

- [ ] `src/content/software/rust.md` — frontmatter: `name: "Rust"`,
  `docs_repo: "github.com/confium/confium"`,
  `docs_ref: "<pinned-tag>"`, `docs_subtree: "docs"`,
  `install_command: "cargo add confium-core"`,
  `description: "Native Rust workspace — 43 crates."`.
- [ ] `src/content/software/ruby.md` — frontmatter: `name: "Ruby"`,
  `docs_repo: "github.com/confium/confium-ruby"`,
  `docs_ref: "<pinned-tag>"`, `docs_subtree: "docs"`,
  `install_command: "gem install confium"`,
  `description: "Ruby bindings via native extension (magnus + rb-sys)."`.
- [ ] `src/content/software/wasm.md` — frontmatter: `name: "WASM"`,
  `install_command: "npm install @confium/confium-wasm"`. No
  `docs_repo` (uses README + JSDoc only for now).
- [ ] `src/content/specs/*.md` — one file per spec (00-framework-overview,
  01-three-modes, 10-mode1-peer-tc, 11-mode2-pki-replacement,
  12-mode3-certificate-pki, 42-transparency-log, 90-security-model).
  Frontmatter: `title`, `description`, `upstream_path` (e.g.
  `specs/00-framework-overview.adoc`).
- [ ] `src/pages/software/[id]/index.astro` — landing page per binding
  with install command, description, link into `/docs/`.
- [ ] `src/pages/software/[id]/docs/[...slug].astro` — renders pages
  from `vendor/{repo}/docs/` via the `softwareDocs` collection.
  Internal `.adoc` links rewritten to on-site routes.
- [ ] `src/pages/software/[id]/docs/index.astro` — index over the
  binding's docs (uses upstream README.adoc if present, else a generated
  listing).
- [ ] `src/pages/specs/[id].astro` — renders spec from `vendor/specs/`
  via `specDocs` collection.
- [ ] `src/pages/specs/index.astro` — index listing all specs.
- [ ] `scripts/fetch-sources.mjs` succeeds locally — populates
  `vendor/confium/docs/`, `vendor/confium-ruby/docs/`, `vendor/specs/`.
- [ ] Failure mode: if a repo is unreachable, build degrades gracefully
  (warning logged, the affected routes return a "docs unavailable"
  page, NOT a build failure).
- [ ] Cross-link audit: every internal `.adoc` link in the pulled docs
  resolves to an on-site route or an external GitHub URL.
- [ ] Search indexes the pulled docs (Pagefind picks them up after
  build).

## Anti-patterns

- Hardcoding ref to `main` — pin to a tag so a broken upstream commit
  can't take the site down.
- Inlining the pulled docs into `src/content/` — that creates merge
  conflicts with upstream. Always go through `vendor/`.
- Skipping the failure-mode test — verify by deliberately pointing at
  a nonexistent repo and confirming the build still succeeds.

## Approach

Single PR. Order: write software metadata files → write specs metadata
files → write the dynamic route handlers → test fetch-sources locally
→ test failure mode → cross-link audit.

## Related

- [032-rust-workspace-docs.md](032-rust-workspace-docs.md) — creates
  the content this TODO pulls.
- [033-ruby-docs-augmentation.md](033-ruby-docs-augmentation.md) —
  creates the content this TODO pulls.
- [034-astro-site-scaffolding.md](034-astro-site-scaffolding.md) —
  establishes `fetch-sources.mjs` and the `softwareDocs`/`specDocs`
  collection shapes.
