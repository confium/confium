# 048 — `/software/` extensions for tools

**Category**: Documentation
**Severity**: Medium (visibility for non-CLI binaries)
**Effort**: Small (3 new entries in the software collection)

## Problem

The `/software/` collection currently has 3 entries: rust, ruby,
wasm. The `confium` CLI, `confiumd` daemon, and
`confium-pkcs11-server` are first-class deployable artifacts but
are buried in the workspace map.

## Acceptance criteria

- [ ] `src/content/software/cli.md` — the `confium` CLI as a
  separately-installable product.
- [ ] `src/content/software/daemon.md` — the `confiumd` service.
- [ ] `src/content/software/pkcs11-server.md` — the PKCS#11 adapter.
- [ ] Each has install command, description, weight for hub ordering.
- [ ] `/software/` hub page renders all 6 cards cleanly.

## Related

- [045-cli-reference-pages.md] — CLI gets full reference; this is
  the install-landing counterpart.
- [046-tooling-pages.md] — same for the other binaries.
