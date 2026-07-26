# 58 — Threat model (comprehensive)

## Adversary capabilities

### Tier 1: Script kiddie / opportunistic

- Network attacker (MITM attempts)
- Phishing director credentials
- Malware on director laptop (limited capabilities)

**Defense**: TLS, password hygiene, antivirus. Trivial.

### Tier 2: Organized crime / ransomware

- Sophisticated malware
- Insider threat (compromised staff)
- Supply chain attacks (compromised dependency)

**Defense**: Threshold crypto (1 compromised director insufficient),
code signing, cargo-deny, defense-in-depth.

### Tier 3: Nation-state (targeted)

- 0-day exploits
- Coercion / compelled disclosure
- Side-channel attacks (timing, power)
- Long-term cryptanalysis investment

**Defense**: Threshold crypto with high T, hardware tokens (YubiKey CSPN),
memory hygiene, transparency logs (compelled-issuance detection),
auditable ceremony protocol.

### Tier 4: Quantum adversary (future)

- Breaks discrete-log crypto (ECDSA, Ed25519, RSA)
- Cannot break symmetric (AES-256, SHA-256, SLH-DSA)

**Defense**: PQ migration path (per `TODO.roadmap/35`). Composite signatures
maintain verifier back-compat. Threshold ML-KEM protects archival data.

## Attack surface

### 1. Coordinator service

- **Compromise**: attacker sees commitments + shares (but threshold property
  preserved; cannot reconstruct secret from < T shares)
- **DoS**: attacker floods coordinator; sessions fail; mitigated by
  multiple coordinators
- **Forged commitments**: prevented by director identity-key signatures

### 2. Director hardware (YubiKey + laptop)

- **YubiKey theft**: requires passphrase + 6-8 digit PIN. Brute-force blocks
  after N attempts. Mitigation: duress code, emergency re-share.
- **Laptop compromise**: ephemeral share in `Sensitive<T>` memory.
  Mitigation: proactive refresh monthly.
- **Passphrase leak**: attacker needs both YubiKey + passphrase.
  Mitigation: hardware token, not just password.

### 3. Network (transport)

- **MITM**: prevented by TLS / per-message signatures
- **Replay**: prevented by session-nonce in every protocol message
- **Traffic analysis**: addressed by message padding where feasible

### 4. Plugin / registry

- **Tampered plugin**: prevented by publisher signature verification
- **Rogue publisher**: revocation workflow via transparency log
- **Dependency confusion**: prevented by cargo-deny sources config

### 5. Algorithm

- **Discrete-log break (P-256, Ed25519)**: catastrophic for those algorithms;
  mitigated by composite signatures + PQ migration
- **Hash collision (SHA-256)**: unlikely for decades; mitigated by ERS
  archival with periodic re-hash
- **Side-channel (timing)**: addressed in well-implemented crates
  (`p256`, `ring`)

### 6. Institutional

- **Compelled issuance** (government forces CA to issue fraudulent cert):
  mitigated by transparency log (catches silent issuance)
- **BIML capture** (BIML staff coerced): mitigated by T-of-N threshold
  (BIML alone cannot sign)
- **Treaty withdrawal** (member state exits, demands their keys back):
  mitigated by share re-sharing (no key recovery possible)

## Trust roots

| Trust root | Compromise impact | Recovery |
|---|---|---|
| BIML root signing cert | All CNML certs forgeable | Root renewal ceremony |
| BIML identity CA cert | Director identity forged | Identity CA re-issuance |
| Bitcoin blockchain | OTS proofs invalid | Use alternative anchor |
| Publisher root keys | Malicious plugins trusted | Registry-wide revocation |
| HSM firmware | Per-device compromise | Replace HSMs |

## Byzantine fault tolerance

For T-of-N threshold signing:

- **T-1 Byzantine**: cannot sign (threshold property)
- **T Byzantine**: can sign anything (catastrophic, but requires collusion)
- **Identifiable abort**: Byzantine party's misbehavior detected and proven

For N-of-N operations (e.g., re-sharing):

- Any non-cooperating party blocks the operation
- Mitigation: re-share with T-of-N, not N-of-N

## Defense in depth

| Layer | Defense |
|---|---|
| Hardware | YubiKey / HSM (keys never leave) |
| Memory | Sensitive<T> zeroize + mlock |
| Process | Confium sandbox (WASM / out-of-process) |
| Transport | TLS + per-message signatures |
| Coordinator | Threshold property (cannot reconstruct from < T shares) |
| Quorum | T-of-N requires collusion of T parties |
| Transparency | Public log catches compelled/silent issuance |
| Audit | Every action logged with director signatures |
| Ceremony | Annual in-person verification (root operations) |

## Specific attack scenarios

### Scenario A: Director coerced during signing

- Director forced to participate in signing they didn't intend
- **Mitigation**: duress code on YubiKey PIN (wipes share locally, alerts coordinator)
- **Mitigation**: 2-phase commit (request + 24h delay + confirm) for sensitive operations

### Scenario B: Coordinator compromised

- Attacker controls coordinator; can drop/add commitments, delay aggregation
- **Mitigation**: threshold property preserved; cannot forge signatures
- **Mitigation**: multiple coordinators; signers submit to all; aggregation requires any to succeed
- **Limitation**: can DoS specific sessions (withhold aggregation)

### Scenario C: All T directors compromised simultaneously

- Attacker can produce any signature under quorum's key
- **Mitigation**: nothing prevents this if T parties truly collude
- **Mitigation**: transparency log detects unauthorized issuance after the fact
- **Mitigation**: high-stakes deployments use higher T (e.g., 5-of-7)

### Scenario D: Algorithm deprecation (e.g., P-256 broken tomorrow)

- All P-256 signatures become forgeable
- **Mitigation**: composite signatures (Ed25519 + ML-DSA-65) maintain security
- **Recovery**: root renewal ceremony with new algorithm suite

### Scenario E: Side-channel attack on signing implementation

- Attacker extracts secret scalar via timing/power analysis
- **Mitigation**: constant-time implementations (`p256`, `ring` are CT)
- **Mitigation**: HSM-resident keys for high-stakes deployments

## Anti-goals

- **Not** perfect security (impossible)
- **Not** protection against T-of-N collusion (out of scope by definition)
- **Not** quantum resistance today (composite PQ migration is the path)

## References

- `TODO.roadmap/08-security-model.md`
- `TODO.roadmap/53-failure-modes-and-incident-response.md`
- `TODO.roadmap/57-privacy-and-data-minimization.md`
