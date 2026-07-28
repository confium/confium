# 047 — Adapter deep-dive pages

**Category**: Documentation
**Severity**: High (Mode 2 is "drop-in PKI replacement"; needs substance)
**Effort**: Medium (4 adapter pages + diagrams)

## Problem

Mode 2 (PKI Drop-in) is the integration story for existing PKI
consumers. The current docs mention PKCS#11 / OpenSSL / JCE / TLS
adapters but don't explain how they actually work. An architect
evaluating Confium can't tell what config the adapter expects,
how the consumer connects, or what the failure modes are.

## Acceptance criteria

- [ ] `/docs/adapters/pkcs11/` — full PKCS#11 v3.0 server config,
  slot/token model, how consumers connect (OpenSSL, Java, custom).
- [ ] `/docs/adapters/openssl/` — OpenSSL 3.0 provider config,
  EVP_PKEY dispatch, nginx/Apache integration.
- [ ] `/docs/adapters/jce/` — Java JCE provider, KeyStore
  integration, sample Java code.
- [ ] `/docs/adapters/tls/` — TLS 1.3 signature callback for
  nginx/Apache/HAProxy.
- [ ] Each page embeds `AdapterPatternDiagram` plus a tool-specific
  diagram (PKCS11AdapterDiagram, OpenSSLProviderDiagram — TBD in 049).

## Related

- [046-tooling-pages.md] — covers the binaries; this covers the
  integration patterns.
- [049-tooling-diagrams.md] — produces the supporting SVGs.
