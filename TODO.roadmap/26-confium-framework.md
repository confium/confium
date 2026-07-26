# 26 — Confium framework vision

## The thesis

**Confium is a general framework for multi-stakeholder threshold
cryptography**, supporting three layered deployment modes that
address progressively deeper use cases:

- **Mode 1 — Peer-to-peer threshold cryptography**: nodes on the
  internet do TC directly, no PKI required. (MPC, distributed
  custody, BFT consensus signing.)
- **Mode 2 — TC PKI replacement (drop-in)**: existing PKI consumers
  (web TLS, code signing, email signing, PKCS#11 apps) replace
  single-party keys with threshold keys **without changing their
  ecosystem**. Includes PQC migration path.
- **Mode 3 — TC Certificate PKI (custom formats)**: organizations
  with their own certificate/document formats and workflow semantics
  (OIML CNML, BIPM calibration, pharma approvals, accreditation,
  supply chain, treaty orgs).

The modes are layered: Mode 3 builds on Mode 2 builds on Mode 1.
A deployment can use any mode or combination. CNML (Mode 3
flagship, `TODO.roadmap/27`) is the proof; Modes 1 and 2 are the
broader adoption surface.

Confium is to threshold cryptography what TLS libraries are to
transport security: a configurable framework organizations deploy
with their own parameters, not a single-purpose system.

## How the modes relate

```
Mode 3: TC Certificate PKI  (CNML, BIPM, pharma, accreditation)
   └─ adds: custom formats, scoped delegation, transparency, archival
        ↓ builds on
Mode 2: TC PKI replacement   (web TLS, code signing, PKCS#11, PQC migration)
   └─ adds: X.509 certs, CMS/TLS envelopes, PKCS#11 server, RFC compliance
        ↓ builds on
Mode 1: Peer-to-peer TC      (MPC, custody, BFT, wallets)
   └─ adds: nothing — pure protocol execution between authenticated peers
        ↓ builds on
Confium primitives           (sig + enc + reshare + coordinator + hardware)
```

## Mode 1 — Peer-to-peer threshold cryptography

### Definition

N nodes on the internet do threshold cryptography directly with
each other. No PKI, no hierarchy, no certificates (beyond mutual
TLS or Noise for transport auth). They run a session, exchange
messages, produce output.

### Audience

Cryptography engineers, distributed systems engineers, blockchain
developers, MPC application builders, applied researchers.

### Examples

- Distributed key custody (cryptocurrency wallets, KMS clusters)
- BFT consensus signature production (validators, distributed ledgers)
- Multi-party computation with secret-output revelation
- Sealed-bid auctions (encrypted bids, threshold-open at close)
- Privacy-preserving analytics (threshold-decrypt aggregate results)
- Distributed build/signing pipelines (multiple build agents collaborate)
- Threshold SSH jump hosts (bastion cluster signs session certs)
- Distributed database encryption (TDEK held across regions)

### Architecture used

- `confium-tc` — session primitives
- `confium-net-tcp` / `confium-net-quic` / `confium-net-ws` — transport
- One algorithm crate (`confium-tc-frost-ed25519`, etc.)
- `confium-store` for share persistence
- Mutual TLS or Noise Protocol for transport auth
- Optional: `confium-tc` (reshare) for committee evolution
- Optional: `confium-tc` (kem) + threshold enc crate for confidential output

### Time to value

Hours. Drop crate, write ~50 lines, run session.

### PQC angle

Pluggable. Pick `confium-tc-frost-ml-dsa-65` or `confium-tc-ml-kem`
when ready.

## Mode 2 — TC PKI replacement

### Definition

Existing PKI consumers (web servers, code signers, email signers,
VPN gateways, database encryption, PKCS#11 applications) replace
single-party keys with threshold keys **without changing their
surrounding ecosystem**. Browsers still verify TLS normally;
OpenSSH still works; OpenSSL still works. The PKCS#11 token they
talk to is actually a Confium threshold coordinator dispatching to
a quorum behind the scenes.

### Audience

Corporate security teams, CA operators, DevSecOps architects,
HSM-using enterprises, government PKI operators.

### Examples

- **Web TLS for high-value sites** — root CAs, payment gateways,
  treasury portals, government sites. TLS handshake normal; server
  signing key threshold-held across multiple data centers.
- **Code signing at scale** — software vendors signing release
  artifacts. Multiple build/release agents collaborate per signature.
- **Corporate S/MIME email signing** — outbound email threshold-signed.
- **VPN gateway authentication** — enterprise VPN cluster shares
  threshold identity.
- **Database TDEK** — transparent data encryption key threshold-held
  across regions.
- **DNSSEC zone signing** — TLD or enterprise zone signing with
  threshold key.
- **DKIM email signing** — corporate domain threshold-signed.
- **CA root key management** — internal CA root keys threshold-held
  for compromise resilience.
- **PKCS#11 drop-in** — any application already using PKCS#11
  (OpenSSL, OpenSSH, Java KeyStore, etc.) gets threshold keys with
  no code changes.

### Architecture used

- Everything from Mode 1
- `confium-cert` for X.509 cert + CSR
- **`confium-pkcs11-server`** — exposes PKCS#11 v3.0 API
  (`C_Sign`, `C_Decrypt`, `C_GenerateKeyPair`, etc.); internally
  dispatches to threshold protocol. **The killer feature for
  Mode 2 — unlocks every existing PKCS#11 application with zero
  code changes.**
- **`confium-openssl-provider`** — OpenSSL 3.0 provider that uses
  Confium for signing
- `confium-pki` (cms feature) for PKCS#7 / CMS envelope compatibility
- `confium-tls-signer` for TLS handshakes that satisfy via threshold
- HSM-backed share storage (PKCS#11, TPM)
- Optional: `confium-composite` for PQ hybrid signatures
- Optional: `confium-transparency` for high-value deployments

### Time to value

Days to weeks. Deploy coordinator, configure HSM, integrate with
existing PKI, test failover.

### PQC angle (critical differentiator)

Confium's PQ path is a major Mode 2 selling point. An enterprise
deploying Confium for PKCS#11 today gets:

- **2026**: threshold Ed25519/ECDSA via PKCS#11 server
- **2027**: threshold ML-DSA-65 composite with Ed25519 (verifier
  back-compat) via PKCS#11 server
- **2028+**: PQ-only when ecosystem ready
- **All without changing the PKCS#11 interface applications see.**

Without Confium, the same enterprise would have to: upgrade all
HSMs to PQ-capable firmware, re-do threshold protocols for new
algorithms, re-issue all credentials. Confium makes this a
software upgrade.

### Strategic partnerships

- **HSM vendors** (Yubico, Thales, Utimaco, AWS CloudHSM) — they
  want threshold features but won't build them; Confium becomes
  the recommended library
- **PKI suite vendors** (HashiCorp Vault, DigiCert, Entrust) —
  integration partnerships
- **Cloud providers** (AWS KMS, GCP KMS, Azure KV) — their
  customers want threshold; Confium provides the standard layer

## Mode 3 — TC Certificate PKI

### Definition

Organizations with their own certificate/document formats and
workflow semantics. Custom delegation rules, custom verification
pipelines, custom archival rules.

### Audience

Institutional system architects — government tech leads, treaty
org CIOs, regulator CTOs, accreditation body directors.

### Examples

- **OIML CNML** (flagship) — type approval certificates with
  model-bound delegation, 5-tier hierarchy
- **BIPM calibration** — SI-traceable calibration certificates
- **Pharmaceutical regulator** — drug applications, GMP certs
- **Academic accreditation** — diplomas with department/university/
  accreditor tiers
- **Financial audit firms** — audit attestations with engagement/
  partner/firm tiers
- **Supply chain provenance** — regulator/certifier/manufacturer/
  shipper/customs
- **Standards bodies** — ISO/IEC standards with working group/
  committee/body tiers
- **Treaty organizations** — international agreements with
  multi-national signatories

### Architecture used

Everything from Mode 2 + custom configuration manifest + custom
document formats + custom delegation rules + transparency log +
archival + audit. Detailed in `TODO.roadmap/27`.

### Time to value

Months. Design manifest, integrate, test, deploy, train.

## Architecture layers

```
Layer 1: Confium primitives (algorithm-agnostic, deployment-agnostic)
   ├─ Threshold sig protocols (FROST, CMP20, GG18, ...)
   ├─ Threshold enc protocols (ElGamal, ECIES, ML-KEM, ...)
   ├─ Re-sharing + proactive refresh
   ├─ Async coordinator service
   ├─ Plugin loader + interface registry
   ├─ Cert path validation
   ├─ Hardware backends (PKCS#11, TPM, OpenPGP, cloud KMS)
   ├─ Transparency log + OTS anchoring
   └~30 crates, all published to crates.io

Layer 2: Confium configuration + integration
   ├─ Mode 1: minimal config, just session params
   ├─ Mode 2: PKCS#11 server config, OpenSSL provider config,
   │          algorithm choices, HSM backend
   └─ Mode 3: deployment manifest with tier structure, quorum T/N,
              attribute predicates, delegation rules, async policies,
              transparency log policy

Layer 3: Deployment (concrete instance)
   ├─ Mode 1: peer apps running Confium crates
   ├─ Mode 2: enterprise PKCS#11 + OpenSSL integration
   └─ Mode 3: OIML CNML (flagship), BIPM calibration, future deployments
```

Layer 1 is the same across all modes. Layer 2 is what makes each
deployment unique. Layer 3 is the running instance.

## Audiences and adoption flywheel

### Audience map

| Mode | Audience | Volume | Revenue per user | Time to value |
|---|---|---|---|---|
| Mode 1 | Developers, researchers | High | Low (OSS) | Hours |
| Mode 2 | Enterprise PKI operators | Mid | High (subscription/support) | Days-weeks |
| Mode 3 | Institutional architects | Low | Highest (integrator model) | Months |

### Expansion strategy per audience

**Mode 1 (developers)** — biggest volume:
- Rust crypto community, arewevcryptoyet.com
- Academic conferences (RWC, CRYPTO, EUROCRYPT, USENIX Security) with artifact evaluations
- Cookbook + FFI examples for Python/Go/C
- "Awesome threshold crypto" curated list
- Hackathon sponsorships
- Plugin contribution pathway (these users often BUILD new algorithm plugins which enriches the framework)

**Mode 2 (PKI operators)** — most revenue potential:
- RSA Conference, Black Hat, DEF CON, EuroPKI presence
- Vendor partnerships with HSM manufacturers (Yubico, Thales, Utimaco)
- Standards body participation: IETF CFRG/LAMPS/TLS, NIST MPTS/PQC, CA/Browser Forum
- Compliance certifications: FIPS 140-3, Common Criteria, SOC 2
- Industry analyst (Gartner, Forrester) briefings
- Case studies: "Company X replaced their HSM-cluster signing with Confium"
- Open source the framework, sell support/enterprise edition/managed coordinator

**Mode 3 (institutions)** — highest impact per deployment:
- Targeted BD to specific organizations
- NIST relationship is cornerstone — NIST MPTS evaluators become champions
- Case study cascade: CNML → BIPM → pharma → supply chain → ...
- Ribose integrator model (revenue from deployment services)
- Academic validation: papers in top venues lend credibility
- Government grant funding (EU Horizon, NSF, national CTO offices)

### The flywheel

The three modes reinforce each other:

1. Mode 1 developers contribute plugins → enriches framework
2. Mode 2 PKI operators provide enterprise credibility, fund compliance certifications, generate case studies
3. Mode 3 institutional deployments produce academic papers, prove research-frontier features, generate press
4. Academic papers drive Mode 1 developer interest
5. Enterprise case studies drive Mode 2 operator adoption
6. Press coverage drives Mode 3 institutional leads

Each mode's success amplifies the others. CNML (Mode 3 flagship)
is not just an end in itself — it's the proof that drives Mode 1
and Mode 2 adoption.

## Configuration model

A Mode 3 deployment is described by a signed **deployment manifest**
(`confium.toml`). Mode 2 uses a simpler config; Mode 1 needs no
manifest.

```toml
# Example Mode 3 skeleton — OIML CNML configuration
[deployment]
name = "OIML CNML"
operator = "BIML"
charter_url = "https://oiml.org/..."
manifest_version = 1

[[tier]]
name = "biml_root"
role = "international root"
signing_algorithm = "FROST-ed25519+ML-DSA-65-composite"
encryption_algorithm = "ML-KEM-768-threshold"
threshold = { t = 5, n = 7 }
attributes = ["region", "expertise"]
ceremony = { sync_required = true, frequency = "annual" }

[[tier]]
name = "ia"
role = "national issuing authority"
signing_algorithm = "FROST-P256"
encryption_algorithm = "ElGamal-P256-threshold"
threshold = { t = 2, n = 3 }
delegated_by = "biml_root"
ceremony = { sync_required = false }

# ... (TL, manufacturer_model, manufacturer_instance tiers)

[transparency]
log_operator = "biml"
anchors = ["bitcoin-ots"]
public_mirror_urls = [...]

[async_signing]
default_unlock_window_minutes = 240
coordinator_operator = "biml"

[archival]
renewal_period_years = 5
re_sign_under = "current-algorithm-suite"
```

This manifest is published; verifiers can read it to understand
the deployment's rules.

```toml
# Example Mode 2 skeleton — enterprise PKCS#11 server
[deployment]
name = "Acme Corp PKI"
mode = "pkcs11_replacement"

[pkcs11_server]
slot_count = 8
default_signing_algorithm = "FROST-P256"
default_threshold = { t = 3, n = 5 }
share_storage = "pkcs11-wrap"           # HSM holds wrapping key
hsm_module = "/usr/lib/pkcs11/yubihsm.so"

[quorum.enterprise_root]
threshold = { t = 3, n = 5 }
coordinator = "coordinator.acme.corp"

[pqc_migration]
current = "ECDSA-P256"
target_2027 = "composite-ECDSA-P256-ML-DSA-65"
target_2029 = "ML-DSA-65"
```

Mode 1 needs no manifest — it's just session parameters in code.

## Research-frontier contributions (general)

These contributions advance the framework itself, applicable across
modes:

1. **Multi-tier hierarchical threshold with delegated signing** —
   configurable tier structure with bounded scope delegation (Mode 3)
2. **Post-quantum composite threshold signatures** — composite
   (classical + PQ) at the threshold layer (Modes 2, 3)
3. **Threshold ML-KEM with proactive security** — long-term
   confidential archival under PQ adversary (Modes 1, 2, 3)
4. **Async threshold signing with coordinator** — globally
   distributed signers, no simultaneity required (all modes)
5. **Share re-sharing with public-key preservation** — committee
   evolution without re-issuance cascade (Modes 2, 3)
6. **Byzantine identification with administrative-grade proof** —
   signed evidence sufficient for proceedings (all modes)
7. **Multi-decade archival with periodic re-quorum** — "living
   will" cryptography for institutions (Mode 3)
8. **Confidential threshold with accountability** — threshold ring
   signatures (research, long horizon; Modes 1, 3)
9. **PKCS#11 dispatch to threshold protocol** — drop-in compatibility
   for every existing PKCS#11 application (Mode 2)

Each contribution is a paper with Confium as reference implementation.

## Engineering scope

### Threshold signing crates (all modes)

| Crate | Algorithm | Status |
|---|---|---|
| `confium-tc-frost-ed25519` | FROST over Ed25519 | shipped |
| `confium-tc-cmp20` | CMP20 over ECDSA P-256 | shipped |
| `confium-tc-gg18` | GG18 over ECDSA P-256 | shipped |
| `confium-tc-frost-p256` | FROST over ECDSA P-256 | new — P0 |
| `confium-tc-bls` | Threshold BLS for cross-org aggregation | new — P2 |
| `confium-tc-frost-ml-dsa-65` | Threshold ML-DSA-65 (research) | new — P1 |

### Threshold encryption crates (all modes)

| Crate | Purpose | Priority |
|---|---|---|
| `confium-tc` (kem) | Threshold KEM session interface | P0 |
| `confium-tc-elgamal-p256` | Threshold ElGamal | P1 |
| `confium-tc-ml-kem` | **Threshold ML-KEM (FIPS 203) — research** | P1 |
| `confium-tc-ecies-p256` | Threshold ECIES | P2 |
| `confium-tc-fhe-bfv` | Threshold BFV FHE (research) | P3 |

### Mode 2 specific — PKI replacement interface shims

| Crate | Purpose | Priority |
|---|---|---|
| `confium-pkcs11-server` | Exposes PKCS#11 v3.0; dispatches to threshold protocol | **P0 — Mode 2 cornerstone** |
| `confium-openssl-provider` | OpenSSL 3.0 provider using Confium for signing | P0 |
| `confium-tls-signer` | TLS 1.3 signature callback satisfying via threshold | P1 |
| `confium-jce-provider` | Java Cryptography Extension provider (Java KeyStore compat) | P2 |

### Mode 3 specific — institutional configuration

| Crate | Purpose | Priority |
|---|---|---|
| `confium-deployment` | Deployment manifest schema + validation | P0 |
| `confium-pki` (delegation feature) | Scoped delegation templates | P0 |
| `confium-pki` (xmldsig feature) | XMLDSig + Exclusive C14N (CNML uses) | P0 |
| `confium-transparency` (ers) | RFC 4998 Evidence Record Syntax | P1 |
| `confium-attributes` | Attribute-based threshold party selection | P2 |
| `confium-ring` | Threshold ring signatures (research) | P3 |

### Framework infrastructure (all modes)

| Crate | Purpose | Priority |
|---|---|---|
| `confium-cert` | X.509 v3 cert + CSR types, path validation | P0 |
| `confium-pki` (cms feature) | CMS/PKCS#7 SignedData envelope | P0 |
| `confium-deployment` | Actor identity: signing + encryption keypairs | P0 |
| `confium-tc` (coordinator) | Async session coordinator (multi-quorum, multi-tenant) | P0 |
| `confium-tc` (reshare) | Share refresh + dynamic committee re-sharing | P0 |
| `confium-transparency` (ots) | OpenTimestamps client + verifier | P1 |
| `confium-transparency` | Append-only Merkle tree with OTS-anchored roots | P1 |
| `confium-composite` | Composite (multi-alg) signature aggregation | P1 |

### Hardware backends (all modes, standards-only)

| Crate | Standard | Status |
|---|---|---|
| `confium-store-pkcs11` | PKCS#11 v3.0 | extend existing |
| `confium-store-tpm` | TPM 2.0 | extend existing |
| `confium-store-cloud` | AWS/GCP/Azure KMS REST | extend existing |
| `confium-store-openpgp-card` | OpenPGP card | new — P0 |

### Extended existing crates

| Crate | Extension |
|---|---|
| `confium-tc` | `SessionParams` gains `quorum_id`, `attribute_predicate`, `unlock_window` |
| `confium-tc` | `SessionResult` gains `signed_proof_of_misbehavior` |
| `confium-tc` | Async session lifecycle states |
| `confium-tc-frost-ed25519`, `confium-tc-cmp20` | Expose identifiable abort via FFI |
| `confium-sandbox-wasm` | Browser signing client (any mode) |
| `confium-net-ws` | WebSocket transport for async sessions |

## Hardware standards — no vendor lock-in

Industry-de-facto standard interfaces only. No vendor-specific SDKs.

| Backend | Standard | Covers |
|---|---|---|
| PKCS#11 (OASIS v3.0) | All HSMs | YubiKey PIV, SoftHSM, AWS CloudHSM, Thales Luna, Utimaco |
| TPM 2.0 (TCG) | All modern hardware | Laptops, servers, IoT |
| OpenPGP card | Open standard | YubiKey OpenPGP applet, Nitrokey, Gnuk |
| WebAuthn / FIDO2 | W3C standard | Browser-native authentication |
| Cloud KMS (REST) | Open APIs | AWS KMS, GCP KMS, Azure Key Vault |
| Android Keystore / iOS Secure Enclave | Platform | Mobile signing |

The wrapped-share pattern works across all of these uniformly.
Explicitly out of scope: any vendor SDK. If a vendor offers a
non-standard API, the answer is "implement PKCS#11 or stay
unsupported."

## Transparency infrastructure (framework-level)

Every Mode 3 deployment gets append-only Merkle tree transparency
with OTS anchoring. Mode 2 deployments opt in for high-value use
cases. Mode 1 rarely needs transparency.

```
Deployment operates its own append-only Merkle tree of all issued
artifacts (certs, signatures, revocations, re-sharing events)
   ↓ tree root periodically committed to Bitcoin via OTS
   ↓ tree published on deployment's website + IPFS mirror
Verifier (offline): downloads Merkle branch + OTS proof
   → proves "this artifact was in the tree as of block N"
```

## Crate publishing — parsanol-rs conventions

Following the parsanol-rs pattern, all public Confium crates
publish to crates.io.

### Workspace metadata

```toml
[workspace.package]
version = "0.1.0"
edition = "2024"
authors = ["Ribose Inc. <open.source@ribose.com>"]
license = "MIT"
repository = "https://github.com/confium/confium"
homepage = "https://confium.org"
rust-version = "1.85"
```

### Per-crate metadata

Every published crate carries `description`, `documentation`,
`keywords`, `categories`, `rust-version`, `readme`, with
`metadata.docs.rs` set to `all-features = true`.

### CI workflows

| Workflow | Purpose |
|---|---|
| `ci.yml` | fmt + clippy + test + deny + machete on every PR |
| `release.yml` | release-plz on push to main → auto version bump, changelog, crates.io publish |
| `docs.yml` | Deploy RustDoc to docs.rs mirror on confium.org |
| `release-binary.yml` | Static `confium` CLI binaries for Linux/macOS/Windows |
| `wasm.yml` | `confium-wasm` artifact published to npm |

### Downstream rebuild triggers

When `confium-core` publishes, trigger rebuild of:
- `confium-ruby` (Ruby bindings via FFI)
- `confium.github.io` (Jekyll site)
- `rnp-rs` (RNP bindings)
- CNML project (OIML SMART, Mode 3 flagship)
- Future: any downstream deployment or integration

## Demonstration strategy

### Mode 1 demonstrations

- 5-minute quickstart tutorials (peer-to-peer signing, MPC)
- Cookbook recipes on docs.confium.org
- FFI examples for Python/Go/C calling Confium
- WASM demo: browser-based MPC
- Conference demos at RWC, RustConf

### Mode 2 demonstrations

- `confium-pkcs11-server` deployed alongside OpenSSL, signing
  certs via threshold protocol (zero OpenSSL code changes)
- "Replace your HSM with a Confium cluster" tutorial
- Case study: enterprise code-signing deployment
- RSA Conference booth demo

### Mode 3 demonstrations

- **OIML CNML** (Q3 2026 – Q2 2027) — flagship deployment.
  Detailed in `TODO.roadmap/27`. NIST MPTS submission Q2 2027.
- **BIPM calibration** (potential, post-Q2 2027) — second
  deployment, validates framework generality.
- **One non-metrology deployment** (potential, post-Q3 2027) —
  demonstrates Mode 3 applies beyond metrology. Candidate:
  pharmaceutical regulator or financial audit firm.
- **Reference deployment profiles** (ongoing) — pre-built
  `confium.toml` templates for common organizational patterns.

## Why this framing works as an adoption driver

- **Framework, not single-purpose system.** Three modes cover
  virtually every threshold cryptography use case.

- **Mode 1 builds developer mindshare.** Open source developers
  adopt Confium for peer-to-peer TC; many contribute plugins.

- **Mode 2 builds enterprise revenue.** PKCS#11 drop-in is the
  enterprise Trojan horse — every PKCS#11 app is a potential
  Confium consumer.

- **Mode 3 builds institutional credibility.** CNML and similar
  deployments prove the framework at the highest stakes.

- **PQ migration is the Mode 2 killer feature.** Enterprises
  facing PQ transition can either replace all their HSMs or
  deploy Confium. Software wins.

- **Real flagship.** OIML CNML anchors the framework in real
  institution-grade deployment, not toy examples.

- **Real research output.** Each paper cites Confium as reference
  implementation; each deployment adds to the corpus.

- **Real publishing pipeline.** Crates on crates.io, docs on
  docs.rs, downstream consumers auto-rebuilt.

## Anti-goals / scope discipline

- **Not** a single-mode system. All three modes are first-class.
- **Not** a single-deployment system. CNML is one Mode 3
  configuration; the framework must support many.
- **Not** a new transparency log architecture. Append-only Merkle
  tree + OTS anchoring. CoSi is a future enhancement.
- **Not** a new PKI. X.509 v3, CMS, XMLDSig — all standardized.
- **Not** "blockchain for X." OTS anchoring is sufficient.
- **Not** general-purpose attribute-based signatures formally.
  ABT predicates scoped to organizational needs.
- **Not** any vendor-SDK-backed HSM integration. Standards only.
- **Not** the workflow orchestrator. Multi-tier composition lives
  in the deployment application.
- **Not** a NIST gatekeeper. Confium provides the bench, not the
  verdict.

## Open questions (framework-level)

1. **PQ threshold schedule.** Threshold ML-KEM and ML-DSA are
   research-frontier. Approach academic collaborator after classical
   system fully deployed (post-Q2 2027).

2. **Composite signature standardization.** IETF COMPOSITE SIG
   draft in flux. Ship current and re-version, or wait for FIPS
   800-208A final?

3. **Funding.** Framework scope is ~18-24 months. Mode 1 work
   is OSS; Mode 2 work may attract enterprise funding; Mode 3
   work may attract government grants.

4. **PKCS#11 server scope.** Full PKCS#11 v3.0 is huge. MVP is
   sign + decrypt + generate-key-pair + minimal key management.
   What's the minimum to call it a real drop-in?

5. **OpenSSL provider vs engine.** OpenSSL 3.0 deprecated engines
   in favor of providers. Provider is the right target. Engine
   compatibility for OpenSSL 1.1 if needed.

6. **NIST transparency log hosting.** Does NIST host a mirror of
   deployment transparency logs (independent verifier anchor)?

7. **Cross-organization recognition.** When deployment A's
   certificates need to be recognized by deployment B (e.g., OIML
   MAA pattern), what's the cryptographic composition? BLS
   aggregate? Multi-sig? Threshold-over-deployment-quorums?

8. **Configuration schema versioning.** As deployments evolve,
   their manifests change. How do verifiers handle manifest
   version skew?

9. **Plugin compatibility across deployments.** A deployment
   might require specific plugin versions or features. How does
   the plugin registry express deployment-specific requirements?

## Reference

- `TODO.roadmap/00-vision-and-mission.md` — why NIST MPTS matters
- `TODO.roadmap/04-threshold-cryptography.md` — TC interface design
- `TODO.roadmap/08-security-model.md` — memory, sandbox, audit
- `TODO.roadmap/09-nist-evaluation-harness.md` — eval bench
- `TODO.roadmap/25-nist-threshold-call.md` — the deadline
- `TODO.roadmap/27-cnml-deployment.md` — Mode 3 flagship case study
- `~/src/oimlsmart/digital-certificates/README.md` — CNML project
- `~/src/parsanol/parsanol-rs/release-plz.toml` — publishing template
- [IETF COMPOSITE SIG draft](https://datatracker.ietf.org/wg/lamps/documents/)
- [RFC 4998 Evidence Record Syntax](https://www.rfc-editor.org/rfc/rfc4998)
- [FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST MPTS 2026 workshop](https://csrc.nist.gov/events/2026/mpts2026)
- [OASIS PKCS #11 v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [OpenSSL 3.0 Provider API](https://www.openssl.org/docs/manmaster/man7/provider.html)
- [TCG TPM 2.0](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Herzberg et al., "Proactive Secret Sharing," 1995](https://www.cs.cornell.edu/people/rafael/papers/ProactiveSecretSharing.ps)
- [FROST draft-irtf-cfrg-frost-13](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/)
