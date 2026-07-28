# 034 — Astro 7 site scaffolding (replaces Jekyll)

**Category**: Documentation
**Severity**: Critical (foundation for all subsequent website work)
**Effort**: Large (one big PR — full stack replacement)

## Problem

`confium.github.io/` is a thin Jekyll site dragging a dead
`confium-dot-org/` React/Paneron attempt. The user directed a full
replacement with the Astro 7 + Vite 8 + Tailwind 4 + Vue islands stack,
architecturally identical to the sister project RNP's site at
`~/src/rnp/rnpgp.org/`.

This TODO establishes the scaffolding so subsequent TODOs (035–043) can
layer content on top.

## Acceptance criteria

- [ ] `astro.config.mjs` mirrors RNP's (Vue + sitemap integrations,
  Tailwind via `@tailwindcss/vite`, `trailingSlash: 'always'`,
  `compressHTML: true`, dual Shiki themes).
- [ ] `package.json` pins: astro@7.1.1, vue@3.5.40, @astrojs/vue@7.0.1,
  @astrojs/sitemap@3.7.3, @astrojs/rss@4.0.19, tailwindcss@4.3.3,
  @tailwindcss/vite@4.3.3, @tailwindcss/typography@0.5.20,
  asciidoctor@4.0.4, yaml@2.9.0, pagefind@1.5.2, plus
  @fontsource/ibm-plex-sans + ibm-plex-mono.
- [ ] `tsconfig.json` extends `astro/tsconfigs/strict`.
- [ ] `src/styles/global.css` — Tailwind 4 with dual-token system
  (`@theme` brand tokens, `:root`/`.dark` semantic vars,
  `@theme inline` bridge). Confium amber palette per plan.
- [ ] `src/lib/asciidoc.ts` — port of RNP's custom Astro loader.
  YAML frontmatter split, `asciidoctor.js` render (`safe: 'safe'`,
  `sectids`, embedded), TOC extraction, internal `.adoc` link rewriting.
- [ ] `src/lib/events.ts` — typed event bus (`openSearch`, `replayHero`).
- [ ] `src/content.config.ts` — defines 9 collections (6 hand-written +
  3 vendor-pulled) per plan.
- [ ] `src/layouts/BaseLayout.astro` — root HTML, theme detect,
  View Transitions, mounts SiteHeader + SiteSearch + SiteFooter.
- [ ] `src/layouts/DocsLayout.astro` — 3-column (sidebar + prose + TOC).
- [ ] Minimal `src/components/vue/{SiteHeader,SiteSearch,ThemeToggle}.vue`
  — functional but not yet styled. TODO 035 enhances.
- [ ] `src/components/astro/{SiteFooter,Prose,TocNav,PageHero}.astro`.
- [ ] `src/components/brand/{SymbolLogo,Wordmark}.astro` — salvage
  existing SVG from `assets/symbol.svg`.
- [ ] `scripts/fetch-sources.mjs` — sparse-checkout of
  `confium/docs/`, `confium-ruby/docs/`, `specs/specs/` into `vendor/`.
  Reads `src/content/software/*.md` for repo + ref + subtree metadata.
- [ ] `scripts/prepare-dev-search.mjs` — copies `dist/pagefind/` to
  `public/pagefind/` for dev server.
- [ ] `.github/workflows/deploy.yml` — Node 22, `npm ci`,
  `npm run fetch-sources`, `npm run build` (prebuild fetch + postbuild
  pagefind), Pages deploy.
- [ ] `.github/workflows/links.yml` — lychee against `dist/`.
- [ ] **Salvage** `assets/symbol.svg`, `assets/nlnet-banner.svg`,
  `assets/ngi-zeropet-banner.svg` into `public/assets/`.
- [ ] **Archive** `confium-dot-org/` to `archive/legacy-paneron/` — flag
  for user sign-off *before* executing.
- [ ] Delete Jekyll scaffolding: `_config.yml`, `Gemfile`, `index.adoc`,
  `custom-intro.html`, `nav-links.html`, `project-nav.html`,
  `about.markdown`, `_pages/`, `_sass/`, `parent-hub/`, `paneron.yaml`,
  `README.adoc`, `404.html`.
- [ ] `.gitignore` adds `vendor/`, `node_modules/`, `dist/`,
  `.astro/`.
- [ ] `npm install && npm run build` succeeds locally with no content.
- [ ] Site builds in CI and deploys to GitHub Pages.

## Anti-patterns

- Keeping any Jekyll file "just in case" — full replacement, no shims.
- Inlining Tailwind via PostCSS instead of `@tailwindcss/vite` — RNP
  uses the Vite plugin path, follow that.
- Skipping the dual-token CSS system — semantic vars enable dark mode
  without per-component overrides.
- Vendoring RNP's easter-egg / fingerprint playground components —
  off-brand for a security framework.

## Approach

Single PR. Order: salvage → archive (with user sign-off) → delete →
scaffold config → scaffold layouts → scaffold minimal components →
fetch-sources script → workflow. Land with an empty homepage so the
site is live; TODO 035 fills it in.

## Related

- [035-homepage-vue-islands.md](035-homepage-vue-islands.md) — fills
  the homepage + adds the interactive Vue islands.
- [041-software-bindings-specs-pull-through.md](041-software-bindings-specs-pull-through.md)
  — depends on `fetch-sources.mjs` working.
- [043-search-cross-link-audit.md](043-search-cross-link-audit.md) —
  verifies Pagefind end-to-end.
