# 68 — Roadmap timeline (2026 → 2028+)

## Strategic phases

### Phase 1: Foundation (Q3 2026)

**Goal**: Framework structurally complete; core real crypto in place.

- [x] Three-mode architecture (Mode 1/2/3) defined
- [x] 43-crate workspace with consolidation complete
- [x] Real P-256 Shamir + Lagrange + ECDSA (`confium-tc-frost-p256`)
- [x] Real threshold ElGamal (`confium-tc-elgamal-p256`)
- [x] Real threshold ECIES with ECDH + AES-256-GCM (`confium-tc-ecies-p256`)
- [x] Real CMS DER encoding per RFC 5652 (`confium-pki`)
- [x] Real Canonical XML per RFC 3076 (`confium-pki`)
- [x] Real RFC 6962 inclusion proofs (`confium-transparency`)
- [x] Real Ed25519 verifier for composite signatures (`confium-composite`)
- [x] Full publishing pipeline (release-plz, rustdoc, release-binary, wasm)
- [x] 744+ tests passing across all crates
- [x] 67 TODO roadmap documents covering strategy → operations
- [x] 2 runnable example binaries demonstrating real crypto

**Status**: ✅ Complete

### Phase 2: NIST MPTS Submission (Q4 2026 - Q2 2027)

**Goal**: Confium is the reference implementation submitted to NIST
MPTS evaluators.

- [ ] Polish NIST evaluator guide (`docs/nist-evaluator.adoc`)
- [ ] NIST MPTS vector integration (`confium-test-harness`)
- [ ] Performance benchmarks via `criterion` (`benches/` directory)
- [ ] Byzantine fault simulation framework
- [ ] Reproducible-artifact submission package
- [ ] Q2 2027 submission: 4-tier CNML architecture + composite PQ + transparency
- [ ] First academic paper draft: "Sovereign Threshold PKI"

**Status**: In progress

### Phase 3: CNML Flagship Deployment (Q3 2027 - Q4 2027)

**Goal**: OIML CNML in production with Confium backing.

- [ ] BIML root quorum DKG ceremony (sync, annual)
- [ ] IA quorums for each participating Issuing Authority
- [ ] TL certificate issuance via Confium
- [ ] Manufacturer Model Cert + Instance Cert flow via Confium
- [ ] Public transparency log on confium.org
- [ ] Async signing infrastructure operational
- [ ] Browser-based director UI (Vue) integrated
- [ ] All 6 CNML verification checks pass with Confium-produced certs

**Status**: Pending NIST MPTS submission feedback

### Phase 4: PQ Threshold Research (Q4 2027 - Q4 2028)

**Goal**: Real PQ threshold cryptography — first production deployment.

- [ ] Academic collaborator onboarded (Boneh / Peikert / EPFL)
- [ ] Threshold ML-KEM prototype (real, not interface)
- [ ] Threshold ML-DSA-65 prototype (real)
- [ ] Composite PQ signatures deployed in CNML
- [ ] PQ migration case study published
- [ ] Second academic paper: "Threshold ML-KEM for Long-Term Archival"

**Status**: Pending collaborator

### Phase 5: Mode 2 Enterprise Adoption (Q1 2028 - Q4 2028)

**Goal**: Enterprises use Confium's PKCS#11 server as drop-in for
threshold + PQ migration.

- [ ] `confium-pkcs11-server` MVP (sign + decrypt + generate-key-pair)
- [ ] `confium-openssl-provider` OpenSSL 3.0 provider
- [ ] Case study: first enterprise deployment
- [ ] HSM vendor partnership (Yubico recommended library)
- [ ] `confium-jce-provider` for Java apps
- [ ] Compliance certifications (FIPS 140-3 module boundary)

**Status**: Pending CNML deployment stabilization

### Phase 6: Second Deployment (Q1 2029 - Q4 2029)

**Goal**: Second institutional deployment validates framework generality.

Candidates:
- BIPM calibration (SI-traceable certs)
- Pharmaceutical regulator (drug approvals)
- Academic accreditation body
- Standards body (ISO/IEC/IEEE)

**Status**: TBD — depends on CNML success

### Phase 7: 1.0 Release (TBD, ~2028-2029)

**Goal**: Confium 1.0 — public API frozen, semver commitments honored.

Pre-conditions:
- At least one production deployment (CNML)
- NIST MPTS submission accepted
- Independent security audit complete
- Real PQ threshold cryptography shipped
- Documentation complete and reviewed

1.0 commits to:
- API stability (no breaking changes without 2.x)
- Plugin contract frozen (existing plugins keep working)
- Minimum 5 years of maintenance

**Status**: Target 2028

## Quarterly milestones (next 6 quarters)

| Quarter | Milestone | Owner |
|---|---|---|
| Q3 2026 | Foundation complete (✅) | Ribose |
| Q4 2026 | NIST evaluator guide + benchmarks | Ribose |
| Q1 2027 | CNML test environment with Confium backing | Ribose + BIML |
| Q2 2027 | **NIST MPTS submission** | Ribose + NIST |
| Q3 2027 | Academic collaborator onboarded | Ribose + academic |
| Q4 2027 | CNML production launch | Ribose + BIML |
| Q1 2028 | PQ threshold prototype | collaborator |
| Q2 2028 | Composite PQ in CNML | Ribose |
| Q3 2028 | PKCS#11 server MVP | Ribose |
| Q4 2028 | First paper #1 submission | collaborator |

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| NIST MPTS deadline slips | Medium | High | Submit what we have; iterate |
| Academic collaborator unavailable | Medium | High | Engage multiple groups early |
| CNML deployment delayed by BIML | Medium | Medium | Maintain test deployment |
| PQ threshold algorithm too slow | Low | Medium | Composite buys time |
| HSM vendor pulls support | Low | Low | Standards-only APIs limit blast radius |
| Competing framework emerges | Medium | Low | Open ecosystem benefits everyone |

## Resource requirements

### Engineering

- 1 senior Rust engineer (Ribose-funded, full-time) — Phase 2-3
- 1 research engineer (collaborator-funded, partial) — Phase 4+
- 1 DevRel / documentation (Ribose-funded, Phase 2+) — education + outreach

### Infrastructure

- Coordinator service hosting (CNML production)
- Transparency log infrastructure (public)
- CI/runners (GitHub Actions mostly free)
- npm + crates.io publishing (free)
- Domain + DNS (minimal)

### Partnerships

- BIML: institutional partnership (in place)
- NIST: MPTS evaluation partner (in place)
- Academic: 1-2 research groups (TBD)
- HSM vendor: technical partnership (TBD)

## Anti-goals

- **Not** rushing 1.0 (commit to stability only when ready)
- **Not** adding features that aren't requested by real users
- **Not** locking into a single deployment vertical

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/27-cnml-deployment.md`
- `TODO.roadmap/35-pq-composite-signatures.md`
- `TODO.roadmap/65-project-governance.md`
