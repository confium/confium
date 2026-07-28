# 045 — `/docs/cli/` reference

**Category**: Documentation
**Severity**: Critical (user-facing complaint: "where is the CLI?")
**Effort**: Medium (one PR — ~12 doc pages + nav integration)

## Problem

A user reports "Confium is missing a CLI". The CLI exists
(`crates/confium-cli`, 9 commands, 14 passing tests, 7 of 9
functional) but the website barely mentions it. There is no
dedicated CLI reference, no install command on the homepage, no
per-command documentation.

## Acceptance criteria

- [ ] `/docs/cli/` overview page (install + command list + concepts).
- [ ] Per-command reference pages mirroring manpage structure
  (SYNOPSIS, DESCRIPTION, OPTIONS, EXAMPLES, EXIT STATUS, SEE ALSO):
  - `install`, `remove`, `update`, `list`, `info`, `search`,
    `trust`, `config`, `version`.
- [ ] `/docs/cli/daemon/` for `confiumd` (separate binary).
- [ ] `/docs/cli/publish/` for `confium-publish` (plugin author tool).
- [ ] Install command added to homepage `InstallTabs` (new "CLI" tab).
- [ ] `/docs/getting-started/` first-line install includes
  `cargo install confium-cli`.
- [ ] `/audiences/developers/` quickstart references the CLI.

## Approach

Mirror RNP's manpage collection structure. Each command file
follows the same template so future commands slot in without
layout decisions.

## Related

- [044-fix-stale-cli-comments.md] — prerequisite for honest docs.
- [046-tooling-pages.md] — sibling for non-CLI binaries.
