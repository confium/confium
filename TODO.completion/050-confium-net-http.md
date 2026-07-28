# 050 — `confium-net-http` implementation

**Category**: Functional
**Severity**: High (unblocks CLI install/update commands)
**Effort**: Large (new crate + wiring)

## Problem

The CLI's `install` and `update` commands are stubs because real
network fetching awaits `confium-net`. The commands use
`NoopDownloader` and can't actually download plugins.

## Acceptance criteria

- [ ] `crates/confium-net-http/` crate implementing HTTP fetching
  via `reqwest` (or equivalent).
- [ ] Trait `Downloader` extracted in `confium-registry` so the CLI
  can swap `NoopDownloader` for `HttpDownloader`.
- [ ] `install` command actually downloads plugins, verifies SHA-256,
  stages them locally.
- [ ] `update` command checks the registry for newer versions and
  applies them.
- [ ] Unit tests + integration tests with a mock HTTP server.
- [ ] Documented in `docs/installation.mdx` and the CLI reference.

## Approach

Start with the trait extraction in `confium-registry` (so the
boundary is clean), then add `confium-net-http` as a workspace
crate, then wire it into the CLI.

## Related

- [044-fix-stale-cli-comments.md] — once this lands, the comments
  flip from "stub" to "functional".
- [045-cli-reference-pages.md] — once install/update work, the
  docs reflect real behavior.
