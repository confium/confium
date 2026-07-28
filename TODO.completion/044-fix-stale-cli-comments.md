# 044 — Fix stale CLI comments in confium-rs

**Category**: Documentation
**Severity**: High (code comments materially misrepresent CLI state)
**Effort**: Small (one PR — comment updates only)

## Problem

`crates/confium-cli/src/main.rs` opens with:

> "Only `version` is implemented today; every other command prints a
> 'not yet implemented' notice and exits with status 2."

**This is materially wrong.** 14 tests pass across the CLI; 7 of 9
commands have real implementations (`version`, `remove`, `list`,
`info`, `search`, `trust`, `config`). Only `install` and `update`
are stubs, blocked on the `confium-net` networking crate.

Anyone reading the source concludes the CLI is a stub. This blocks
honest documentation on the website.

## Acceptance criteria

- [ ] `main.rs` header comment updated to reflect actual state.
- [ ] Per-command file headers accurate: `install.rs` and `update.rs`
  clearly marked as awaiting `confium-net`; others reflect their real
  behavior.
- [ ] `TODO.roadmap/07-cli-tools.md` references in command headers
  removed or updated (the design doc shouldn't be referenced from
  public-facing code comments).
- [ ] CLI tests still pass: `cargo test -p confium-cli`.

## Related

- [045-cli-reference-pages.md] — depends on accurate code comments.
