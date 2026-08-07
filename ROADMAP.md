---
title: Confium Roadmap
description: Six-month and twelve-month direction for the Confium project
date: 2026-08-07
status: accepted
---

# Confium Roadmap

This roadmap captures the project direction at a glance. For day-to-day tasks see [TODO files](https://github.com/confium/confium/tree/main/TODO.restructure); for architectural direction see [Architecture](./architecture.mdx).

**Status:** Accepted (2026-08-07). Reviewed quarterly.

## Vision (12 months)

Make Confium the default open-source framework for distributed cryptographic trust — the same relationship OpenSSL has to transport security, but for threshold signing, transparency, and PKI.

Concretely, by 2027-08:

- **All 6 products** (Threshold, Transparency, PKI, Keyless, Privacy, Verify) are at production maturity with real-world deployments
- **5 language bindings** (Rust, Ruby, Python, WASM/TypeScript, Go, Node) at full feature parity
- **NIST MPTS** evaluation complete; Confium is a reference implementation for threshold signature test vectors
- **Multiple CAs** operate threshold CA deployments on Confium in production
- **Browser-side verification** of Confium signatures is as common as PGP signature verification in OSS release tooling

## Themes (6 months)

### Theme 1 — Production hardening
Move every shipped crate from "implementation complete" to "production-grade":
- chaos testing in `confium-coordinator`
- HSM-backed share storage in production
- multi-region DKG ceremonies
- graceful shutdown / failover in `confium-signerd`
- audit log immutability via transparency log anchoring

### Theme 2 — PQ migration
Composite signatures ship stable (Ed25519 + ECDSA-P256 today); add:
- ML-DSA-65 (FIPS 204) threshold via `confium-tc-frost-ml-dsa-65`
- SLH-DSA-SHA2-256 composite (FIPS 205)
- LMS composite for archival
- Threshold ML-KEM (FIPS 203) for hybrid KEMs

### Theme 3 — Keyless ubiquity
- GitHub Action: `uses: confium/action@v1` in every major OSS release workflow
- PyPI / RubyGems / npm packages signed via Confium Keyless
- Browser extension: verify Confium signatures on any GitHub release page

### Theme 4 — Privacy in production
Move privacy primitives from research-grade to production-grade:
- PSI: 2-party at 10M-element scale
- MPC: SPDZ with online/offline phase separation
- DP: persistent budget tracking across queries

### Theme 5 — Transparency at scale
- 1B-entry logs on commodity hardware
- witness gossip across 25+ independent witnesses
- OTS anchoring cadence: 10 min (vs 1 hr today)
- ERS archival to public Internet Archive

### Theme 6 — UX polish
- 5-minute quickstart for every product (no more)
- Confium Playground: in-browser DKG + sign + verify, no install
- Confium Inspector: GUI for inspecting signatures / proofs / certs

## Per-product themes

### Threshold
- ✅ CMP20, GG18, FROST-P256, FROST-Ed25519 shipped
- 🚧 Real Paillier MtA in production (currently stubbed in-process)
- 🚧 Share refresh in production (Herzberg)
- 🚧 signerd production deployment guide

### Transparency
- ✅ RFC 6962 inclusion + consistency proofs
- 🚧 Witness gossip multi-witness topology
- 🚧 Public log infrastructure (Confium-operated, like Certificate Transparency)
- ❌ Verifiable data structures beyond Merkle (e.g., Revocation Trees)

### PKI
- ✅ X.509 cert/CSR/CMS, XMLDSig
- ✅ Composite signatures (PQ migration)
- 🚧 PKCS#11 v3.0 full coverage
- 🚧 OpenSSL 3.0 provider in production
- ❌ JCE provider in production (skeleton only today)

### Keyless
- ✅ GitHub Actions OIDC integration
- ✅ Short-lived cert format
- 🚧 PyPI / RubyGems / npm keyless integration
- ❌ Browser extension for in-page verify

### Privacy
- ✅ PSI, PIR, DP, MPC, ring sigs shipped (15+ primitives)
- 🚧 Production-scale PSI (10M elements)
- 🚧 Persistent DP budget across restarts
- ❌ Anonymous credentials in production

### Verify
- ✅ WASM verifier, Python, Ruby, Node bindings
- ✅ HTTP verify server
- 🚧 Go binding to full parity
- ❌ Real-time verify dashboard reference implementation

## What's NOT on the roadmap (so you don't wait)

These are deliberately excluded; if you need them, fork:

- **ZK proofs of arbitrary computation** (Confium uses ZK for specific statements: set membership, signature possession, attribute satisfaction — not general-purpose zkSNARKs)
- **FHE in production** (`confium-tc-fhe-bfv` is research-grade; production FHE is out of scope until hardware acceleration matures)
- **Per-product repos** (staying in monorepo; see [Repo Strategy](./architecture/repo-strategy.mdx))
- **Commercial / enterprise edition** (BSD-2-Clause forever; no open-core)
- **Blockchain-specific features** (Confium is chain-agnostic; blockchain integrations live in downstream repos)
- **Mobile SDKs** (iOS / Android bindings are out of scope until demand materializes)

## Versioning

See [docs/policies/versioning.mdx](./policies/versioning.mdx). In short:

- 0.x → 0.y: minor breaks allowed, called out in CHANGELOG
- 1.0+: strict semver; breaking changes require 2.0
- 1.0 lands when 5 of 6 products are production-grade

## Roadmap changes

Material changes to this document require maintainer consensus per [GOVERNANCE.md](../GOVERNANCE.md).
