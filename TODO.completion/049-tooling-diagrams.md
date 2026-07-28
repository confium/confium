# 049 — Tooling SVG diagrams

**Category**: Documentation
**Severity**: Medium (visual support for new content)
**Effort**: Small (4 diagram components)

## Problem

The CLI, adapters, and daemon pages need diagrams to explain
architecture. The existing `AdapterPatternDiagram` covers Mode 2
at a high level; tooling-specific diagrams are missing.

## Acceptance criteria

- [ ] `CLIArchitectureDiagram.astro` — how `confium` dispatches to
  registry / config store / signer processes.
- [ ] `PKCS11AdapterDiagram.astro` — slot/token model + dispatch
  into Confium coordinator.
- [ ] `OpenSSLProviderDiagram.astro` — EVP_PKEY → provider → Confium.
- [ ] `DaemonArchitectureDiagram.astro` — `confiumd` JSON-RPC over
  Unix socket / TCP.

## Related

- [047-adapter-deep-dives.md] — consumes the adapter diagrams.
- [045-cli-reference-pages.md] — consumes the CLI diagram.
