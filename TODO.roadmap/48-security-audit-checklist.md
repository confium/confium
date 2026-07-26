# 48 — Security audit checklist

## Pre-audit readiness

Before engaging a security auditor (NCC Group, Cure53, Trail of Bits, etc.)
for Confium, every item below must be in a known-good state.

### Cryptography

- [ ] All cryptographic primitives use established crates (`p256`, `ed25519-dalek`, `aes-gcm`, `sha2`, `ring`)
- [ ] No hand-rolled crypto primitives (only protocol-level code is original)
- [ ] Random number generation always uses `rand_core::OsRng` or Confium's `rng` interface
- [ ] Constant-time comparisons used for all equality checks on secrets
- [ ] Share zeroization on drop (via `zeroize` crate's `ZeroizeOnDrop` derive)
- [ ] `mlock` on buffers holding secrets (where supported)

### Memory safety

- [ ] `#![forbid(unsafe_code)]` on every crate (audit exception list if any)
- [ ] No raw pointer manipulation
- [ ] No `unsafe` FFI without `// SAFETY:` justification comments

### Authentication / Authorization

- [ ] Every protocol message signed by sender identity key
- [ ] Every coordinator action audit-logged
- [ ] Coordinator authentication (mTLS or token) before accepting sessions
- [ ] Director identity keys certified under BIML identity CA
- [ ] Quorum ID validated on every session create

### Input validation

- [ ] All untrusted input (manifests, certs, signatures, network messages) validated before processing
- [ ] Length-prefixed message framing to prevent memory exhaustion
- [ ] Bounded recursion in parsers (manifest, predicate DSL, XMLDSig)
- [ ] Algorithm identifiers whitelisted (no arbitrary strings)
- [ ] Public key bytes length-validated before parsing

### Threat model coverage

Per `TODO.roadmap/08-security-model.md`:

- [ ] **Malicious plugin**: in-process trust documented; sandbox roadmap (WASM, process) tracked
- [ ] **Tampered artifact**: publisher signature verification on every install
- [ ] **Rogue publisher**: trust root management documented; revocation workflow tested
- [ ] **Network MITM**: TLS required for `quic://`, `tcp+tls://`; per-message signatures otherwise
- [ ] **Memory disclosure**: `Sensitive<T>` zeroizes; `Secret<T>` AEAD-encrypted at rest (post-0.3)
- [ ] **Dependency confusion**: cargo-deny `sources` config enforces provenance

### Fuzzing

- [ ] `fuzz/` directory exists with fuzz targets for: manifest parser, predicate DSL, XMLDSig canonicalizer, transparency log entries, CMS parser
- [ ] CI runs fuzz targets for 1 hour nightly
- [ ] Corpus committed to repo for regression testing

### Test coverage

- [ ] 70%+ line coverage on every published crate
- [ ] 90%+ on cryptographic operations
- [ ] Byzantine fault tests for every threshold algorithm
- [ ] Integration tests cover Mode 1, Mode 2, Mode 3 representative flows

### Side-channel considerations

- [ ] Timing attacks: secret-dependent branches removed where possible
- [ ] Power analysis: documented as out-of-scope for software-only Confium
- [ ] Memory access patterns: documented as research item (ORE, ORAM)

### Operational security

- [ ] Coordinator service runs as non-root
- [ ] Coordinator data directory permissions 0700
- [ ] Audit log rotated and tamper-evident (hash-chained)
- [ ] Backup and disaster recovery documented

## Audit scope

A Confium security audit typically covers:

### Tier 1: Core (always audited)

- `confium-core` (plugin loader, FFI)
- `confium-tc-coordinator` (async session state machine)
- `confium-tc-reshare` (share re-sharing protocol)
- `confium-cert` (X.509 parsing)
- `confium-escrow` (threshold key escrow)

### Tier 2: Algorithms (audited per algorithm)

- `confium-tc-frost-p256` (real P-256 Shamir + ECDSA)
- `confium-tc-elgamal-p256` (real P-256 ElGamal)
- Existing `confium-tc-frost-ed25519`, `confium-tc-cmp20`, `confium-tc-gg18`
- New algorithm crates as they ship

### Tier 3: Interfaces (audit lite)

- All other crates — interface review, not deep audit

## Post-audit workflow

1. Findings categorized as Critical / High / Medium / Low / Info
2. Critical/High: patch in private fork, coordinate disclosure per `SECURITY.md`
3. Medium/Low: schedule for next release
4. Info: document in audit report, no code change

## References

- `TODO.roadmap/08-security-model.md`
- `TODO.roadmap/42-testing-strategy.md`
- `SECURITY.md`
- `TODO.finalize/13-sensitive-memory.md`
