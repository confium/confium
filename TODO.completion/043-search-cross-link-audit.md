# 043 — Search + cross-link audit + CI gates

**Category**: Documentation
**Severity**: High (final quality gate before launch)
**Effort**: Small (one PR — verification + CI wiring)

## Problem

TODOs 034–042 land a lot of content. This TODO verifies it all works
end-to-end: Pagefind search returns relevant results, no links are
broken, and the content constraints (no OIML, no TODO/roadmap language)
hold across the whole site. It also adds CI gates so future regressions
fail the build.

## Acceptance criteria

- [ ] `npm run build` produces `dist/pagefind/` with a non-empty index.
- [ ] `npm run preview` serves the site locally at `localhost:4321`.
- [ ] Manual search smoke test: Cmd+K for "threshold", "FROST",
  "sovereign", "transparency", "PKCS#11" returns relevant results
  from across `/docs/`, `/concepts/`, `/use-cases/`, glossary, and
  blog.
- [ ] `npm run check:links` (lychee) passes against `dist/` with zero
  failures. Pre-existing external 4xx/5xx are added to `.lycheeignore`
  with a comment explaining why.
- [ ] `grep -ri OIML dist/` returns zero hits.
- [ ] `grep -ri 'TODO\|coming soon\|planned\|milestone\|roadmap' dist/`
  returns zero hits. (Allow `TODO` inside `<code>` blocks if any — none
  expected.)
- [ ] Every internal cross-link in `/docs/`, `/concepts/`,
  `/use-cases/`, glossary, blog resolves to a real route.
- [ ] Every external link to `docs.confium.org` (RustDoc) and
  `github.com/confium/*` returns 200.
- [ ] Lighthouse: Performance ≥ 90, Accessibility ≥ 95, Best Practices
  = 100 on the homepage.
- [ ] Mobile viewport (375px) audit: no horizontal scroll, header
  collapses to drawer, all grids reflow.
- [ ] Dark mode toggle persists across pages and reloads; cross-tab
  sync works.
- [ ] View Transitions animate cleanly between page navigations.
- [ ] Sitemap at `/sitemap-index.xml` lists every route.
- [ ] RSS feed at `/rss.xml` validates (use W3C feed validator).
- [ ] `robots.txt` blocks `/vendor/`, `/archive/` (if any).
- [ ] **CI gate added** to `.github/workflows/deploy.yml` (or a new
  `quality.yml`): runs the OIML grep + TODO grep + lychee after build,
  fails the workflow on any hit.
- [ ] README in `confium.github.io/` documents the local dev workflow:
  `npm install && npm run fetch-sources && npm run dev`.

## Anti-patterns

- Skipping the CI gate — without it, content constraints drift.
- Adding `.lycheeignore` entries without comments — future contributors
  won't know why a link is excluded.
- Treating the audit as a final step — run the greps and lychee locally
  before opening the PR, not after CI fails.

## Approach

Single PR. Run the full verification locally; fix any hits; add the CI
gate; document the workflow. The CI gate is the durable artifact —
without it, the next contributor can break the constraints silently.

## Related

- Every other website TODO (034–042) — this is the final verification
  that they all hang together.
