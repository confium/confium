# 035 — Homepage + Vue islands

**Category**: Documentation
**Severity**: Critical (single highest-impact content surface)
**Effort**: Large (one PR — homepage + 6 Vue islands)

## Problem

The homepage is the front door. After TODO 034 lands the Astro
scaffolding with a minimal homepage placeholder, this TODO replaces it
with the seven-section layout from the plan and adds the six
interactive Vue islands that make the page feel alive.

## Acceptance criteria

- [ ] `src/pages/index.astro` renders seven sections in order:
  1. Hero (animated tagline + dual CTA)
  2. Three modes (interactive `ModeSelector.vue`)
  3. What makes Confium different (5 bullets)
  4. What Confium is NOT (3 negations)
  5. Get started (3 install tabs via `InstallTabs.vue`)
  6. Reference deployments (6 sovereign PKI scenarios; CNML is one)
  7. Funding band (NLnet NGI Zero PET banner — salvaged SVG)
- [ ] `src/components/vue/HeroDecrypt.vue` — WAAPI character-decrypt
  animation on the tagline *"Threshold-native trust infrastructure for
  a post-quantum world"`. Replays on `replayHero` event.
- [ ] `src/components/vue/ModeSelector.vue` — three-card picker
  (Peer-to-Peer TC, PKI Drop-in, Sovereign PKI); selected card expands
  with a longer description + CTA. Persists selection in URL hash.
- [ ] `src/components/vue/QuorumPlayground.vue` — interactive T-of-N
  slider (T and N both adjustable, 1 ≤ T ≤ N ≤ 9). Visualizes "no
  single party can sign alone" with party dots lighting up as T is
  reached. Replaces RNP's `FingerprintPlayground.vue`.
- [ ] `src/components/vue/InstallTabs.vue` — Ruby / Rust / WASM / Source
  tab switcher with copy button. Each tab shows the canonical install
  command in a terminal-style block.
- [ ] `src/components/vue/CopyButton.vue` — clipboard copy with
  fallback (`navigator.clipboard` → `execCommand`) + success state.
- [ ] `src/components/vue/Reveal.vue` — IntersectionObserver scroll
  reveal wrapper with `prefers-reduced-motion` opt-out.
- [ ] Hero tagline renders server-side as static text (progressive
  enhancement); the decrypt animation layers on top for capable clients.
- [ ] Every Vue island is `client:load` or `client:visible` as appropriate
  (below-the-fold islands use `client:visible`).
- [ ] Lighthouse: Performance ≥ 90, Accessibility ≥ 95 on the homepage.
- [ ] Mobile viewport (375px): hero text wraps cleanly, mode cards
  stack, quorum playground remains usable.
- [ ] Dark mode: every island respects `.dark` via the semantic token
  system; no hardcoded colors.

## Anti-patterns

- Marketing fluff — every claim must be backed by a link into `/docs/`
  or `/concepts/`.
- "Coming soon" CTAs — only link to live pages.
- Hardcoding color values inside Vue components — use Tailwind classes
  derived from `@theme inline` tokens.
- Auto-playing media — the decrypt animation runs once on load and on
  explicit replay only.

## Approach

Single PR. Build islands in dependency order: CopyButton → Reveal →
HeroDecrypt → InstallTabs → ModeSelector → QuorumPlayground. Each
island gets a quick visual smoke test in `npm run dev` before moving
on. Final commit wires the homepage sections together.

## Related

- [034-astro-site-scaffolding.md](034-astro-site-scaffolding.md) —
  establishes the layouts and Vue integration this builds on.
- [036-docs-pages.md](036-docs-pages.md) — the homepage CTAs link here.
- [039-use-cases-sovereign-pki.md](039-use-cases-pages.md) — the
  Sovereign PKI mode card links here.
