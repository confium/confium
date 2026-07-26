# 56 — Accessibility (a11y)

## Scope

Confium's user-facing surfaces must be accessible:

- CLI output (terminal)
- Documentation site (web)
- Director signing UI (browser, Vue)
- NIST evaluator portal (browser)

## Standards

- **WCAG 2.2 AA** (Web Content Accessibility Guidelines)
- **Section 508** (US federal)
- **EN 301 549** (EU public sector)
- **AX** (general accessibility best practices)

## CLI accessibility

### Output

- Use color only as enhancement; never as the sole indicator
- Detect TTY and disable color when piped
- Always provide text alternatives: `[OK]` not just green checkmark
- Don't rely on emoji for meaning

### Input

- All flags have long-form (`--threshold`) and short-form (`-t`)
- Accept abbreviations for unambiguous long-form flags
- Passwords never echoed; prompt with clear "Enter passphrase:" text
- Validate input and provide helpful error messages

### Screen reader

- Test with `screen` + `espeak-ng` for terminal screen reader compat
- Avoid progress bars that spam screen reader (use `--quiet` for SR users)
- Print clear status messages at start/end of operations

## Web accessibility

### Documentation site

- Semantic HTML5 (`<nav>`, `<article>`, `<aside>`, `<section>`)
- Skip-to-content link as first focusable element
- Color contrast 4.5:1 minimum (AA) for body text
- Color contrast 3:1 minimum for large text and UI components
- All form fields have associated `<label>`
- All images have `alt` text (decorative images: `alt=""`)
- Heading hierarchy: exactly one `<h1>`, logical `<h2>`-`<h6>` nesting

### Director signing UI (Vue island)

- Full keyboard navigation (Tab, Shift+Tab, Enter, Space, Esc)
- Visible focus indicators (3:1 contrast minimum)
- ARIA roles for dynamic content (`role="dialog"`, `aria-live="polite"`)
- Modal traps focus when open
- Form errors announced via `aria-live="assertive"`
- Real-time validation messages readable by screen reader

### Color

- Never color-only status (also include icon + text)
- Test with color blindness simulators (Deuteranopia, Protanopia, Tritanopia)
- Dark mode that maintains contrast ratios

## Localization interaction

Per `TODO.roadmap/50-internationalization.md`:
- All strings translatable
- RTL layouts (Arabic, Hebrew) — left-to-right reading flow reverse
- No hardcoded text in images

## Cognitive accessibility

- Plain language (Flesch-Kincaid grade 8 or below for user-facing text)
- Avoid jargon in onboarding flows
- Provide tooltips / help text for advanced options
- "Are you sure?" prompts for destructive actions
- Undo where possible

## Motor accessibility

- Click targets minimum 44×44 CSS pixels (WCAG 2.5.5)
- Keyboard-equivalent for every mouse action
- No time-limited interactions without extension option
- Drag-and-drop has keyboard alternative

## Audit

- Run automated tools: axe-core, Pa11y, Lighthouse a11y audit
- Manual keyboard-only test on every release
- Annual third-party accessibility audit
- Public statement: `docs/accessibility.md`

## Anti-goals

- **Not** full AAA conformance (some criteria are impractical)
- **Not** perfect — accessibility is a journey, not a destination
- **Not** optional for "minor" UI components

## References

- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/)
- `TODO.roadmap/50-internationalization.md`
