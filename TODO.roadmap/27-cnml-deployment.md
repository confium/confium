# 27 — CNML flagship deployment: OIML sovereign threshold PKI

## CNML is the Mode 3 flagship

Confium supports three layered deployment modes (see
`TODO.roadmap/26`): Mode 1 (peer-to-peer TC), Mode 2 (TC PKI
replacement via PKCS#11 drop-in and PQC migration), Mode 3
(TC Certificate PKI with custom formats and deep workflows).

The OIML Certificat Numérique de Métrologie Légale (CNML) project —
Ribose's existing project at `~/src/oimlsmart/digital-certificates/`,
delivered under the OIML SMART program — is the **Mode 3 flagship
reference deployment**. It demonstrates Confium at the highest-stakes
end of the spectrum:

- **International treaty organization** (OIML, 60+ member states)
- **Nation-state adversary** (cyber + political pressure)
- **Decades-long archival** (instruments last 10-20 years)
- **Sovereignty sensitivity** (no single nation trusted)
- **Globally distributed directors** (async signing required)
- **Annual ceremony cadence** (root operations only)

Partnerships locked in:
- **Ribose** operates OIML SMART, owns CNML, owns Confium
- **BIML** (OIML secretariat) is the institutional partner
- **NIST** partners on MPTS evaluation

This deployment is what NIST MPTS evaluators, OIML member states,
and the cryptographic research community will see as proof that
threshold cryptography solves real governance problems. The
**framework** (`TODO.roadmap/26`) supports all three modes; this
is the Mode 3 deployment that proves it works at the deepest level.

Mode 1 deployments are typically small-scale developer use cases
(distributed custody, MPC, BFT signing) covered by API docs and
examples. Mode 2 deployments are enterprise PKI replacements
(`confium-pkcs11-server` is the cornerstone; future case studies
will follow).

## What's wrong with CNML's status quo

Today CNML uses:

- **Single-party ECDSA P-256** for every signing layer
- **2-of-2 Shamir** for BIML root key — recombined on a signing
  workstation during ceremony (the recovery step is the weak point)
- **Browser IndexedDB** software keys for end-entity signers
- **OpenTimestamps** for blockchain anchoring (good)
- **CRL** for revocation (good, but no accountability)
- **No encryption layer** — confidential test reports stored in
  plaintext, or protected only by transport TLS
- **No async signing** — every ceremony requires synchronous
  coordination, infeasible for globally distributed directors
- **No director rotation without root renewal** — changing the
  threshold party requires changing the keypair, invalidating all
  issued certificates

Confium replaces all of these with framework primitives configured
for CNML's specific tier structure and policies.

## CNML's five-tier configuration

CNML deploys Confium with a **five-tier hierarchy** including
**delegated signing at the manufacturer tier**.

```
BIML Root (OIML directors, threshold 5-of-7, annual ceremony)
  │ signs
  ▼
IA Cert (national Issuing Authority, threshold 2-of-3, async signing)
  │ signs                                       │ signs
  ▼                                             ▼
TL Cert (Testing Lab accreditation)         Manufacturer Model Cert
  │                                             (scoped delegation: manufacturer
  │                                             can issue instance certs for
  │                                             THIS specific model only)
  │                                             │ signs (manufacturer, single-party)
  │                                             ▼
  │                                          Instance Cert (individual measuring
  │                                             instrument, physical or software)
  │
  └─→ signs test report → encrypts to IA threshold KEM
```

| Tier | Signing | Encryption | Threshold | Ceremony |
|---|---|---|---|---|
| **BIML** | Threshold FROST-Ed25519 + ML-DSA-65 composite | Threshold ML-KEM-768 | 5-of-7 directors | Annual sync (root ops); emergency async |
| **IA** | Threshold FROST-P256 | Threshold ElGamal-P256 | 2-of-3 officers | Async |
| **TL** | ECDSA-P256 single-party | ECIES-P256 single-party | 1-of-1 | Async |
| **Manufacturer (Model)** | ECDSA-P256 single-party | ECIES-P256 single-party | 1-of-1 | Async |
| **Manufacturer (Instance)** | ECDSA-P256 single-party | n/a | 1-of-1 | Async |

Each national IA has its own threshold quorum, independently keyed
via its own DKG. Hundreds of distinct IA quorums coexist with the
single BIML root quorum.

### Delegated signing at the manufacturer tier

The IA's Manufacturer Model Certificate is a **scoped delegation**:
it authorizes a specific manufacturer to issue instance certificates
for instruments of a specific model only.

The Model Cert contains:
- Manufacturer identity (name, national registration)
- Model identifier (OIML R-Recommendation, model number, accuracy class)
- Profile / specs hash (binding the model definition cryptographically)
- Validity period (e.g., 5 years)
- Issuance-count limit (optional)
- Delegation scope extension: "may issue instance certs for model X only"

The manufacturer's Instance Certs:
- Reference the Model Cert (X.509 authorityKeyIdentifier)
- Bind to a specific instrument (serial number, manufacturing date)
- Bind to instance-specific data (firmware hash for software;
  hardware measurements for physical)
- Path validation: instance valid only if (a) signed by manufacturer,
  (b) Model Cert valid, (c) Model Cert issued by recognized IA,
  (d) IA cert chains to BIML root, (e) scope check passes

A manufacturer **cannot** issue instance certs for a model it wasn't
approved for. Path validation rejects them.

### Tier-transition cryptography

Every upward tier transition is **sign-then-encrypt-to-recipient-quorum**:

```
Manufacturer → TL:        encrypt(instrument + test plan, tl_pub)
TL → IA:                  encrypt(sign(test_report, tl_priv), ia_threshold_pub)
IA → BIML:                encrypt(escalation, biml_threshold_pub)
IA → Public:              sign(cnml_cert, ia_threshold_priv)
BIML → Public:            sign(ia_cert, biml_threshold_priv)
Manufacturer → Public:    sign(instance_cert, manufacturer_priv)
                          (under Model Cert scope)
```

Confium provides the primitives; the orchestration is the CNML
application's job (`oiml-pki-server` Ruby + browser WASM clients).

### Selective disclosure per artifact

Each artifact has an audience scope, encrypted to the appropriate
recipient:

- **Test plan** — manufacturer + TL only (trade secrets)
- **Test report** — TL + commissioning IA only (one IA, not all IAs
  the TL works with)
- **CNML certificate** — public (signed, transparency-logged)
- **Instance certificate** — public (signed by manufacturer)
- **Revocation evidence** — sealed (threshold-encrypted to BIML
  quorum; decryptable only on court order via quorum ceremony)

## Async signing — the operational model

OIML directors are globally distributed. In-person annual ceremony
is feasible only once per year, only for root operations. **All
IA cert issuance, CNML cert issuance, and routine operations run
async.**

### Async session coordinator (BIML-operated)

A coordinator service operated by BIML staff (one per quorum)
buffers commitments and shares from directors. Directors
participate when convenient — different time zones, different
schedules.

```
Director's laptop (when convenient):
  1. Director opens Confium app
  2. Sees pending signing session (e.g., "IA-France cert issuance")
  3. Reviews cert details
  4. Enters passphrase → YubiKey decrypts wrapping key → share unwrapped
     into Sensitive<T> memory
  5. App generates Round 1 commitment (FROST nonce)
  6. Commitment signed by YubiKey identity key (non-repudiation)
  7. Commitment uploaded to coordinator
  8. Director walks away. Session stays unlocked for ~4 hours
     (configurable; refreshable).

Coordinator (operated by BIML staff):
  9. Detects T commitments received → broadcasts aggregated commitment
  10. Notifies each participating director's app

Director's laptop (later, when convenient):
  11. App generates Round 2 share (session still in unlock window)
  12. Share signed by YubiKey
  13. Share uploaded

Coordinator:
  14. Once T shares received, aggregates → final signature
  15. Signature applied to certificate
  16. Full transcript audit-logged
```

Director active time: ~5 minutes per round. Director never
coordinates with other directors. Total session wall time: hours
to days depending on director availability.

The coordinator is honest-but-curious: it sees commitments and
shares but cannot reconstruct the secret key. Director identity-key
signatures prevent forged commitments. Session unlock window
default: 4 hours (configurable per quorum).

### Annual ceremony — what's done there

The annual ceremony is sacred: in-person, network-isolated,
ambassador-credential-verified. Operations performed:

- **Root DKG** (initial keypair generation, one-time)
- **Root renewal** (new keypair, cross-signed with old, every N
  years for algorithm migration or compromise recovery)
- **Director rotation** (sync re-sharing, in-person verification
  of new directors)
- **Quorum policy changes** (e.g., changing T from 5-of-7 to 6-of-9)
- **Audit review** (physical evidence inspection, transparency log
  reconciliation)

Everything else runs async via the coordinator.

## Director identity and key management

### Standardized hardware, self-generated keys

Two-tier protection: **YubiKey/OpenPGP card proves director identity**
(signs protocol messages, decrypts share wrapping key); **laptop
runs the threshold protocol** with unwrapped share in `Sensitive<T>`
memory.

- **Hardware**: OIML specifies the standard model (e.g., YubiKey 5
  CSPN-certified or OpenPGP card v3.4). Procured centrally by OIML
  to ensure firmware integrity, distributed to directors at ceremony.
- **Key generation**: each director generates their own identity
  keypair on the device, in person, during annual ceremony. No OIML
  escrow of private keys.
- **Registration**: director's public identity key certified under
  BIML identity cert (separate from root signing cert).
- **Share storage**: threshold share stored on disk, encrypted with
  AES-256-GCM under a key wrapped by the YubiKey's PIV decrypt key.
  Share is unusable without physical device + passphrase.

### Why this design

- **No OIML key escrow**: directors generate their own keys
- **Hardware standardization**: consistent security level
- **Two-tier protection**: compromised laptop alone cannot use share
- **Duress codes**: YubiKey PIN can be configured so a special PIN
  wipes the share locally and alerts coordinator

## Director rotation and committee evolution

Two distinct operations, often confused:

| Operation | What changes | Public key | When |
|---|---|---|---|
| **Share re-sharing** | Committee composition (add/remove director) | **Unchanged** | Any time (T current directors collaborate) |
| **Root renewal** | Root keypair itself | **New keypair** | Annual ceremony, every N years |

For director rotation: **share re-sharing preserves the public key**.
All dependent certs (IA certs, CNML certs, instance certs) remain
valid. No re-issuance cascade. This is critical because BIML has
hundreds of IA certs in the field, each potentially with thousands
of CNML certs and millions of instance certs beneath.

### Re-sharing protocol

```
Setup: C_old = {Alice, Bob, Carol, Dave, Eve}, T=3-of-5
       Alice is leaving. Frank is joining.
       C_new = {Bob, Carol, Dave, Eve, Frank}

Step 1: T current directors (e.g., Bob, Carol, Dave) participate
Step 2: Each participating director computes Lagrange interpolation
        of their share at each new party's index:
          For each j in C_new:
            s_j_new = Σ over participating-i of (Lagrange_basis(j, i) * s_i_old)
Step 3: Each new share s_j_new encrypted to party j's YubiKey
        (using party j's registered identity public key)
Step 4: Encrypted shares transmitted
Step 5: All old shares (including participating directors' old shares,
        including departing director's share) destroyed (zeroized)
Step 6: New committee tests: produces signature, verifies it validates
        under same aggregate public key
Step 7: Audit log records entire procedure, signed by all participants
```

Public key unchanged. All existing certs remain valid.

### Scheduling rotations

- **Routine rotation** (director term expires, new director elected):
  sync re-sharing at annual ceremony. In-person verification is the
  trust anchor.
- **Emergency rotation** (director dies, YubiKey lost, director
  compromised): async re-sharing. T current directors run the protocol
  remotely. Documented in audit log with reason.
- **Proactive refresh** (no committee change, just share refresh):
  monthly or quarterly async refresh. Defends against gradual share
  compromise over time.

### Root renewal (rare)

Root renewal generates a **new keypair**. Required for algorithm
migration (Ed25519 → composite PQ), compromise recovery, or periodic
refresh every 10-20 years.

Protocol at annual ceremony:
1. New DKG among current committee produces new root keypair
2. New public key cross-signed by old root (transition cert)
3. Transition cert published in transparency log
4. Old root scheduled for retirement (1-year grace period)
5. During grace: dependents (IAs) re-issue under new root
6. After grace: old root marked revoked, transparency log finalized

## The CNML demo narrative

A CNML certificate for a high-stakes custody-transfer gas flow meter
(OIML R 117 type approval), produced through the full 5-tier flow:

```
Setup (one-time per actor)
  Each IA registered, has BIML-signed IA cert (threshold 2-of-3)
  Each TL registered, has IA-signed TL cert
  Each Manufacturer registered, may receive Model Certs from IAs
  BIML root quorum (5-of-7 directors) — annual ceremony
  All certs public, all in BIML transparency log

Step 1 — Manufacturer develops new instrument model
  Manufacturer designs gas flow meter model "FM-2026-A"
  Submits to IA-France for type approval

Step 2 — IA-France commissions TL for testing
  IA-France threshold quorum signs a commissioning order
  Order encrypted to chosen TL's encryption public key
  TL decrypts, schedules tests

Step 3 — Manufacturer submits instrument to TL
  Manufacturer ships physical instance + test plan
  Test plan encrypted to TL's encryption public key

Step 4 — TL generates test report
  TL runs tests per OIML R 117
  TL signs test report (single-party)
  TL encrypts (test report + signature) to IA-France's threshold
    KEM public key (NOT to all IAs — only the commissioning IA)
  Encrypted blob transmitted to IA-France

Step 5 — IA-France reviews
  IA-France threshold quorum (2-of-3 officers) collaboratively decrypt
  IA verifies TL's signature against TL's certified public key
  IA reviews content, makes determination
  IA threshold-signs internal review record

Step 6 — IA-France issues Manufacturer Model Cert (async BIML pathway)
  IA threshold quorum signs Manufacturer Model Cert
  Model Cert: manufacturer X, model "FM-2026-A", accuracy class 0.5,
    validity 5 years, scope: "may issue instance certs for FM-2026-A only"
  Model Cert committed to BIML transparency log, OTS-anchored

Step 7 — Manufacturer issues Instance Certs (delegated, single-party)
  Manufacturer produces gas flow meter S/N 0001
  Manufacturer signs Instance Cert: serial 0001, model FM-2026-A,
    firmware hash 0x..., manufacturing date, calibration data
  Instance Cert references Model Cert via authorityKeyIdentifier
  Manufacturer uploads Instance Cert to public transparency log
  → Verifier (customs officer) can path-validate:
    Instance Cert → Model Cert → IA-France cert → BIML root
  → Scope check: model in Instance Cert must match Model Cert scope

Step 8 — Field deployment
  Instrument S/N 0001 deployed at a gas pipeline
  Verifier (regulator, customer) scans instrument QR code
  Verifier downloads Instance Cert + chain from public log
  Standard XMLDSig verifier validates chain to BIML root
  OTS proof demonstrates cert existed at deployment time

Step 9 — Optional BIML oversight / high-stakes countersign
  BIML samples some Manufacturer Model Certs for review
  For high-stakes classes (custody-transfer), BIML threshold
    quorum countersigns the Model Cert
  Async — directors participate over hours

Step 10 — Revocation (if needed)
  Issue detected (field failure, lab fraud discovered)
  IA-France threshold quorum revokes Model Cert (signed reason)
  All Instance Certs under that Model Cert auto-revoked via OCSP/CRL
  Manufacturer cannot issue new Instance Certs for that model
  Revocation evidence threshold-encrypted to BIML quorum (sealed)
  Transparency log records revocation with timestamp

Step 11 — Long-term archival
  Test report encrypted under IA-France threshold KEM
  Every 5 years, current IA-France quorum re-encrypts under new KEM
    (no plaintext exposure during re-encryption)
  Survives decades — decryptable only via T-of-N ceremony
```

## Two co-equal cryptographic primitives

CNML uses both threshold signing and threshold encryption at the
institutional tiers.

| Operation | Threshold primitive | CNML use case |
|---|---|---|
| IA cert issuance | **Threshold signing** | BIML quorum signs IA cert (async) |
| TL cert issuance | **Threshold signing** | IA quorum signs TL cert (async) |
| Manufacturer Model Cert issuance | **Threshold signing** | IA quorum signs scoped delegation |
| CNML cert issuance | **Threshold signing** | IA quorum signs CNML cert |
| Test report submission | **Threshold encryption** | TL encrypts to IA; IA quorum decrypts |
| Cross-tier escalation | **Threshold encryption** | IA encrypts to BIML; BIML quorum decrypts |
| Sealed revocation evidence | **Threshold encryption** | IA encrypts evidence; only court-ordered quorum decrypts |
| Long-term calibration data | **Threshold PQ encryption** | Survives quantum adversary for 50+ years |
| Director share wrapping | Single-party encryption | YubiKey-held key wraps share on disk |

## Practical failure modes and recovery

| Scenario | Recovery |
|---|---|
| Director loses YubiKey | Emergency async re-sharing: T remaining directors re-share excluding lost YubiKey's identity. Replacement director issued new YubiKey at next ceremony. |
| Director's laptop compromised | Proactive share refresh (monthly): all current directors refresh; old shares invalidated. |
| Director dies / resigns | Sync re-sharing at next annual ceremony (preferred) or async emergency. |
| Director coerced during signing | Duress code on YubiKey PIN: wipes share locally, alerts coordinator. |
| Coordinator compromised | Threshold property preserved. Director identity-key signatures prevent forged commitments. Coordinator can DoS but cannot corrupt. |
| Quorum cannot form (too many unavailable) | Lower T at next ceremony. Between ceremonies, operations wait. |
| Annual ceremony disrupted (pandemic) | Async emergency re-sharing as fallback. Root renewal deferred. Audit-logged. |
| TL loses signing key | Single-party — TL reissues new key, gets new TL cert from IA. Old reports remain valid (signature already applied). |
| Manufacturer loses signing key | Same as TL: new key, new Model Cert from IA. Old Instance Certs remain valid. |

## CNML-specific engineering scope

Most crates are framework-level (see `TODO.roadmap/26`). CNML adds
configuration and integration:

### CNML-specific configuration

- `confium.toml` deployment manifest encoding the 5-tier hierarchy,
  BIML 5-of-7 + IA 2-of-3 + TL/Mfr 1-of-1 thresholds, attribute
  predicates (geography, expertise, COI), annual ceremony policy,
  model-bound delegation rules
- XMLDSig signing profile scoped to CNML XML schema
- CMS envelope profile for CNML document signatures

### CNML application integration

- `oiml-pki-server` (Ruby) calls Confium via FFI for DKG, signing,
  re-sharing, threshold encryption
- Browser-based director UI (Vue island in CNML Astro app) loads
  Confium WASM, signs via WebSocket to coordinator
- Browser-based TL UI: TLs sign reports, encrypt to specific IA
- Browser-based manufacturer UI: manufacturers issue instance certs
  under their Model Cert scope
- Existing 46 TS + 49 Ruby + 52 Playwright CNML tests pass against
  Confium-backed CA

### CNML-specific deployment artifacts

- BIML transparency log operated by BIML staff
- Per-IA quorum coordinators (operated by IA or by BIML on behalf)
- Annual ceremony runbook (operational, not cryptographic)
- Director training materials (UI walkthrough, passphrase management)

## Demonstration plan

### Audience 1: NIST MPTS evaluators (mandatory, Q2 2027)

Reproducible artifact submitted to NIST's MPTS portal:

- A signed CNML certificate, signed by a 5-of-7 BIML quorum (async)
- A test report, signed by a TL, threshold-encrypted to a 2-of-3 IA
  quorum, threshold-decrypted, then a Manufacturer Model Cert
  threshold-signed by IA
- A Manufacturer Instance Cert, signed by manufacturer under Model
  Cert scope, path-validated
- Async signing demonstrated: director commitments submitted over
  hours, not simultaneously
- Director rotation demonstrated: re-sharing preserves public key
- Standard XMLDSig verifier passes on all public certs
- Byzantine-fault simulation: rogue director caught, signed proof
  emitted in <50ms
- Performance report: signing and encryption ceremony wall times
  across party counts 3, 5, 7, 11

### Audience 2: BIML / OIML member states (operational)

Working integration with the CNML project:

- All CNML tests pass against Confium-backed CA
- Live deployment to BIML test environment
- Public transparency log live on confium.org
- Annual ceremony runbook drafted
- Director training delivered to first cohort

### Audience 3: Academic community (research output, post-Q2 2027)

Three papers, sequenced after classical system deployment:

1. **"Sovereign threshold PKI: international metrology as a case
   study"** — systems paper, USENIX Security or IEEE S&P.
   Contributions: 5-tier architecture, delegated signing, async
   coordinator, share re-sharing deployment.

2. **"Threshold ML-KEM with proactive security for long-term
   archival"** — theory + implementation, CRYPTO or EUROCRYPT.

3. **"Attribute-based threshold signatures for cross-jurisdictional
   governance"** — theory, CCS.

Each paper cites Confium as reference implementation; each has
artifact evaluation pointing at the OIML deployment.

## Timeline

| Quarter | Milestone |
|---|---|
| Q3 2026 | Publish framework core crates to crates.io. Ship `confium-cert` (with scoped delegation), `confium-cms`, `confium-identity`, `confium-store-pkcs11` + `confium-store-openpgp-card` wrapping backends. |
| Q4 2026 | `confium-xmldsig`, `confium-tc-frost-p256`, `confium-tc-kem` interface, `confium-tc-coordinator` v0, `confium-tc-reshare` v0. First end-to-end CNML signature via Confium. |
| Q1 2027 | Async signing flow deployed: director app, coordinator, session lifecycle. Composite signatures. Byzantine-proof FFI. Manufacturer Model Cert + Instance Cert flow. |
| Q2 2027 | `confium-ots`, `confium-transparency` v0, threshold ElGamal. NIST MPTS submission: 5-tier architecture with signing + encryption + async + re-sharing. |
| Q3 2027 | Approach academic collaborator with complete classical system. `confium-tc-ml-kem` research prototype begins. |
| Q4 2027 | `confium-tc-frost-ml-dsa-65` (research). Composite PQ signing ceremony in CNML. |
| Q1 2028 | `confium-ers` archival, periodic re-quorum demo. |
| Q2 2028 | `confium-attributes` ABT, paper #1 submission. |
| Q3 2028 | `confium-ring` (research), paper #2 submission. |
| Q4 2028 | Paper #3 submission, full case study writeup. |

NIST Threshold Call deadline gates Q2 2027. Classical system ships
first; PQ threshold work follows with collaborator onboarded against
a complete reference system.

## CNML-specific open questions

1. **Director identity cert chain.** Director identity keys are
   certified separately from the root signing cert. What CA issues
   the director identity cert? BIML itself (separate identity CA)?
   Needed for async signing non-repudiation.

2. **Re-sharing ceremony documentation.** Sync (annual) vs async
   (emergency) procedures need formal writeup that BIML directors
   can follow. Cryptographic protocol is clear; operational
   procedure (who is in the room, what they verify, what they sign)
   needs CNML-side documentation.

3. **Cross-IA recognition crypto.** OIML MAA pattern: when IA-A's
   CNML is recognized by IA-B. BLS aggregate? Simple multi-sig?
   Threshold-over-IA-quorums?

4. **BIML transparency log infrastructure.** Operated by BIML staff
   on BIML-controlled infrastructure. Where hosted? BIML on-prem?
   Cloud? Distributed across OIML member states for redundancy?

5. **Test report retention policy.** Some OIML Recommendations
   require test report retention for instrument lifetime (10-20
   years). How does this interact with re-encryption cadence and
   quorum evolution?

## Reference

- `TODO.roadmap/26-confium-framework.md` — framework vision (general)
- `TODO.roadmap/00-vision-and-mission.md` — why NIST MPTS matters
- `TODO.roadmap/04-threshold-cryptography.md` — TC interface design
- `TODO.roadmap/08-security-model.md` — memory, sandbox, audit
- `TODO.roadmap/09-nist-evaluation-harness.md` — eval bench
- `TODO.roadmap/25-nist-threshold-call.md` — the deadline
- `~/src/oimlsmart/digital-certificates/README.md` — CNML project
- `~/src/parsanol/parsanol-rs/release-plz.toml` — publishing template
- [FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST MPTS 2026 workshop](https://csrc.nist.gov/events/2026/mpts2026)
- [Herzberg et al., "Proactive Secret Sharing," 1995](https://www.cs.cornell.edu/people/rafael/papers/ProactiveSecretSharing.ps)
- [FROST draft-irtf-cfrg-frost-13](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/)
