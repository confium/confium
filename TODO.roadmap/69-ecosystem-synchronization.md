# 69 — Ecosystem synchronization

## Overview

The Confium project spans multiple repositories. This document tracks
ecosystem-wide synchronization work and is the master reference for
which repos need attention when the framework changes.

## Repositories

### Primary

| Repo | URL | Role | Status |
|---|---|---|---|
| `confium` | https://github.com/confium/confium | Rust workspace (main product) | ✅ 43 crates, 744+ tests, 68 TODO docs |
| `confium-ruby` | https://github.com/confium/confium-ruby | Ruby FFI bindings gem | ✅ Synced 2026-07-26 (PR #8) |
| `confium.github.io` | https://github.com/confium/confium.github.io | Jekyll site for www.confium.org | ✅ Synced 2026-07-26 (PR #11) |
| `specs` | https://github.com/confium/specs | Multi-spec technical repository (deployed to https://www.confium.org/specs/) | ✅ Synced 2026-07-26 (PRs #1 + #2; repo renamed from `confium-report`) |
| ~~`infrastructure`~~ | ~~https://github.com/confium/infrastructure~~ | ~~Terraform for AWS~~ | ❌ Deprecated, ignored. |

### Consumed dependencies

| Repo | URL | Role | Status |
|---|---|---|---|
| `rnp-rs` | https://github.com/rnpgp/rnp-rs | Rust binding to RNP OpenPGP C library | ✅ All 3 Confium BUGREPORTs fixed (commit `ed268d5`) |
| `hash-botan` | https://github.com/confium/hash-botan | Botan hash plugin (extracted from main) | ✅ Standalone |

### Downstream consumers (not Confium repos)

| Repo | URL | Role |
|---|---|---|
| `oimlsmart/digital-certificates` | (private) | OIML CNML project — Mode 3 flagship consumer |
| `parsanol/parsanol-rs` | https://github.com/parsanol/parsanol-rs | Reference for publishing conventions |

## Synchronization matrix

When the framework changes, downstream repos may need updates:

| Framework change | Ruby | Website | Report (specs) | Infrastructure |
|---|---|---|---|---|
| Public FFI surface | Update `lib/confium/ffi.rb` | Docs only | Spec doc update | n/a |
| New crate published | Add bindings if user-facing | Mention in features | Mention in spec | n/a |
| Architecture shift (e.g., three-mode) | README update | Landing page update | New spec document | n/a |
| Version bump | Bump gem version | Docs only | Optional | n/a |
| Crate consolidation (rename) | Update FFI paths | Update feature list | Update spec refs | n/a |
| New production deployment | n/a | New case study | New spec | New DNS/hosting (operator-initiated) |

## Recent synchronization work

### 2026-07-26: Three-mode architecture rollout

Triggered by framework reaching 43 crates + 744 tests + Mode 1/2/3 framing.

- ✅ `confium`: All framework work complete (43 crates, real crypto, 68 TODO docs)
- ✅ `confium.github.io`: PR #11 merged — landing page now describes three modes
- ✅ `confium-ruby`: PR #8 merged — README rewritten, module-level specs added, ecosystem TODO doc created
- ✅ `specs` (renamed from `confium-report`): PR #1 merged — generalized into multi-spec repository with 3 initial spec documents + 6 new SVG diagrams
- ⏭️ `infrastructure`: deprecated, ignored

### 2026-07-26: Crate consolidation (53 → 43)

Triggered by 5 logical merges (PRs #42, #43 in main repo).

- ✅ `confium`: tests preserved (744), CLAUDE.md updated
- ✅ `confium-ruby`: not affected (no Ruby bindings to deleted crates)
- ✅ `confium.github.io`: not affected (no per-crate pages yet)
- ✅ `specs` (formerly `confium-report`): spec 02 (`02-workspace-organization.adoc`) covers the consolidation

## Per-repo status and TODO

### confium (this repo)

✅ **Structurally complete**:

- 43 crates (consolidated from 53 via 5 logical merges)
- 744 tests passing
- Real cryptographic primitives in 7 algorithm/envelope areas
- 68 TODO roadmap documents covering strategy through operations
- 8 runnable example binaries demonstrating all 3 deployment modes
- Full publishing pipeline (release-plz, rustdoc, release-binary, wasm)
- 3 BUGREPORTs filed at rnp-rs (all fixed)

⏳ **Pending work** (tracked in `TODO.roadmap/68-roadmap-timeline.md`):

- Q4 2026: NIST evaluator guide + benchmarks
- Q1 2027: CNML test environment with Confium backing
- Q2 2027: **NIST MPTS submission**
- Q3 2027: Academic collaborator onboarded
- Q4 2027: CNML production launch
- Q1 2028: PQ threshold prototype (collaborator-driven)
- Q2 2028: Composite PQ in CNML
- Q3 2028: PKCS#11 server MVP for Mode 2

### confium-ruby

✅ **Synced 2026-07-26 (PR #8)**:

- README rewritten with three-mode context
- `spec/confium_spec.rb` added for module-level coverage
- `TODO.roadmap/00-ecosystem-sync.md` mirrors this doc

⏳ **Pending work**:

- [ ] Bump gem version to 0.3.0 to match Rust workspace
- [ ] Add bindings for new interfaces: `confium-tc` (threshold signing), `confium-tc-kem` (threshold encryption), `confium-tc` (coordinator — async session)
- [ ] Add integration test that builds Rust workspace and runs against gem
- [ ] Translate high-level framework docs into Ruby-idiomatic examples
- [ ] Mirror Confium's `TODO.roadmap/` strategy for tracking ecosystem work

### confium.github.io

✅ **Synced 2026-07-26 (PR #11)**:

- Landing page (`custom-intro.html`) updated with three-mode architecture
- About page rewritten

⏳ **Pending work**:

- [ ] Blog post: "Confium 0.3 released — three deployment modes"
- [ ] Documentation portal at docs.confium.org (links to RustDoc + examples)
- [ ] CNML case study page (summary of `TODO.roadmap/27-cnml-deployment.md`)
- [ ] NIST MPTS page (summary of `TODO.roadmap/25-nist-threshold-call.md`)

### specs (formerly confium-report)

✅ **Synced 2026-07-26 (PR #1)** — generalized into multi-spec repository:

- README.adoc: master index of ~70 planned spec documents
- 3 initial spec docs shipped:
  - `specs/00-framework-overview.adoc`
  - `specs/01-three-modes.adoc`
  - `specs/02-workspace-organization.adoc`
- 6 new SVG diagrams:
  - `three-mode-architecture.svg`
  - `cnml-tier-hierarchy.svg`
  - `async-session-lifecycle.svg`
  - `share-reshare.svg`
  - `transparency-log.svg`
  - `mode2-pkcs11-dispatch.svg`
  - `plugin-registry.svg`
- Original 2022 `report.adoc` preserved as historical context

⏳ **Pending work** (~40 more spec docs to roll out):

- Mode 1/2/3 detail specs (`specs/10-`, `specs/11-`, `specs/12-`)
- Plugin contract spec (`specs/20-`)
- Threshold session lifecycle spec (`specs/22-`)
- Async coordinator spec (`specs/23-`)
- Share re-sharing spec (`specs/24-`)
- Threshold encryption spec (`specs/25-`)
- Cert/CSR/CMS/XMLDSig specs (`specs/30-` through `33-`)
- Composite signatures spec (`specs/34-`)
- Operational specs (`specs/40-` through `45-`)
- Per-algorithm specs (`specs/50-` through `60-`)
- Mode 2 shim specs (`specs/70-` through `73-`)
- Mode 3 deployment specs (`specs/80-` through `82-`)
- Security/compliance specs (`specs/90-` through `93-`)
- Governance specs (`specs/99-` through `101-`)

Each spec follows the template: conceptual overview, architectural diagram, type definitions, wire formats, behavioral invariants, cross-references to implementation source and TODO.roadmap docs.

### infrastructure

❌ **Deprecated** — per Ribose direction (2026-07-26), the `infrastructure/`
repository is no longer part of the Confium open-source workspace. Any
future infrastructure needs (DNS, coordinator hosting, transparency log
hosting, S3 buckets) will be handled via internal Ribose processes
outside the open-source project. This repository is ignored.

### rnp-rs

✅ **All 3 BUGREPORTs fixed** in commit `ed268d5`:

- `BUGREPORT.detached-revocation-signature-helper.md` — `generate_revocation_certificate()` free functions
- `BUGREPORT.pqc-keypair-with-signing-and-encryption-subkeys.md` — `KeyBuilder::add_pqc_*` builders
- `BUGREPORT.threshold-share-key-import.md` — `ThresholdSigner` trait

No further work needed from Confium side. rnp-rs is being adopted as a
workspace-level dependency for plugin signature verification and PGP
operations.

## Ecosystem-wide principles

### Single source of truth

Each concern has exactly one canonical home:

- **Engineering roadmap**: `confium/TODO.roadmap/` (this repo, 68 docs)
- **API reference**: docs.rs (auto-generated from source)
- **User-facing docs**: `confium.github.io` (Jekyll site)
- **Technical specifications**: `specs/specs/` (multi-spec repo)
- **Ruby bindings**: `confium-ruby/lib/confium/`
- ~~**Infrastructure**: `infrastructure/`~~ Deprecated, ignored
- **Engineering guide**: `confium/CLAUDE.md` (workspace-level)

### Anti-duplication

- Don't copy API reference into the website — link to docs.rs
- Don't copy specs into TODO.roadmap — link to `specs/specs/`
- Don't copy operational runbooks into specs — link to `TODO.roadmap/59-deployment-runbook.md`
- Don't copy code examples into the report repo — link to `confium-examples/src/bin/`

### Synchronization triggers

A change in the main `confium/` repo triggers downstream work only when:

1. **Public FFI surface changes** → Ruby gem update required
2. **User-visible architecture shifts** → Website + report repo update required
3. **New algorithm published** → Per-algorithm spec in report repo
4. **Major version bump** → Ruby gem version bump, release notes everywhere

Routine internal refactors (test additions, doc clarifications, performance optimizations) do NOT trigger downstream work.

## Anti-goals

- **Not** forcing sync across all repos on every framework change — only when user-facing
- **Not** modifying `infrastructure` without operator approval (per CLAUDE.md)
- **Not** auto-generating Ruby bindings from Rust FFI surface (manual curation preferred)
- **Not** duplicating content across repos (link, don't copy)

## References

- `/Users/mulgogi/src/confium/CLAUDE.md` (workspace-level)
- `TODO.roadmap/26-confium-framework.md` (framework vision)
- `TODO.roadmap/65-project-governance.md` (project governance)
- `TODO.roadmap/66-branding-and-trademark.md` (naming conventions across repos)
- `TODO.roadmap/68-roadmap-timeline.md` (multi-year phases)
- `confium-ruby/TODO.roadmap/00-ecosystem-sync.md` (Ruby gem's mirror of this doc)
- `specs/README.adoc` (multi-spec repo index)
