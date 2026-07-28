# 046 — `/docs/tooling/` for non-CLI binaries

**Category**: Documentation
**Severity**: High (production deployments need this)
**Effort**: Medium (one PR — 7 tooling pages)

## Problem

Five binaries ship in the workspace beyond the CLI:
`confiumd`, `confium-publish`, `confium-pkcs11-server`,
`confium-test-harness` (sim), plus the adapter libraries
(`confium-openssl-provider`, `confium-jce-provider`,
`confium-tls-signer`). The website has zero dedicated pages for
any of them.

## Acceptance criteria

- [ ] `/docs/tooling/pkcs11-server/` — Mode 2 adapter.
- [ ] `/docs/tooling/openssl-provider/` — OpenSSL 3.0 provider.
- [ ] `/docs/tooling/jce-provider/` — Java JCE provider.
- [ ] `/docs/tooling/tls-signer/` — TLS 1.3 signature callback.
- [ ] `/docs/tooling/daemon/` — `confiumd` JSON-RPC service.
- [ ] `/docs/tooling/publish/` — `confium-publish` author tool.
- [ ] `/docs/tooling/test-harness/` — NIST MPTS evaluation bench.
- [ ] Each page: what it does, when to deploy, install, config,
  monitoring, common operations.

## Related

- [045-cli-reference-pages.md] — sibling for the CLI itself.
- [047-adapter-deep-dives.md] — adapters get their own deep-dive section.
