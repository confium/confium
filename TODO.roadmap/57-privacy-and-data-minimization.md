# 57 — Privacy and data minimization

## Threat model

Confium handles sensitive data:

- Director identity keys
- Threshold shares (the most sensitive material)
- Confidential test reports (manufacturer trade secrets)
- Calibration data (potentially defense-related)
- Audit logs (contain timing + actor identity metadata)
- Revocation evidence (often sealed for legal reasons)

Privacy threats:

1. **Data leakage via logs**: audit logs inadvertently capture secret bytes
2. **Metadata exposure**: timestamps + actor IDs reveal deployment patterns
3. **Long-term archival disclosure**: encrypted data may be decryptable by future adversaries
4. **Cross-deployment linkage**: same director participating in multiple deployments
5. **Registry tracking**: which plugins a user installs reveals their stack

## Data minimization principles

### Logs

- **Never log secret bytes** (shares, private keys, passphrases)
- **Never log full ciphertexts** — at most length + hash
- **Always redact PII** unless explicitly configured otherwise
- **Default to summary events** (event type + count, no detail)

```rust
// NEVER:
log::info!("Signing with share: {:?}", share.bytes);

// GOOD:
log::info!("Signing with share from party {}", share.party_index);
```

### Network traffic

- **TLS everywhere** (mTLS preferred for coordinator ↔ signer)
- **No PII in URLs** (query parameters are logged by proxies)
- **Constant-size messages where feasible** (pad short messages)

### Storage

- **Shares stored encrypted** (AES-256-GCM via Sensitive<T> wrapper)
- **Yubikey-wrapped at rest**: never plaintext on disk
- **Audit logs encrypted** at rest (filesystem-level encryption)

### Memory

- **Zeroize on drop** (`Sensitive<T>` already does this)
- **mlock sensitive pages** (per `TODO.roadmap/08`)
- **Disable core dumps** while secrets live

## Confidentiality tiers

| Tier | Data | Storage | Transport |
|---|---|---|---|
| Public | Certs, transparency log entries | Plain | HTTP (with OTS) |
| Operational | Audit log metadata | Encrypted at rest | TLS |
| Confidential | Test reports, calibration data | Encrypted + access-controlled | TLS + threshold-encrypted |
| Secret | Threshold shares, identity keys | HSM / YubiKey / Sensitive<T> | Never over network in plaintext |

## Metadata minimization

### Audit log

Audit logs MUST contain enough to reconstruct what happened (transparency
property), but SHOULD NOT contain:

- Director IP addresses (use actor ID only)
- Specific timing of individual signing operations (round to minute)
- Content hashes of confidential payloads (use opaque IDs)

### Transparency log

The transparency log IS public. Entries contain:

- Sequence number
- Timestamp (rounded to second)
- Artifact type
- Artifact hash (this is the point — verifier can confirm artifact was logged)

Trade-off: transparency (public verifiability) vs privacy (confidentiality
of what's being logged). For Mode 3 deployments, transparency wins.

## Cross-deployment privacy

A director participating in multiple deployments (e.g., BIML director + IA
officer in different countries) creates linkage risk.

Mitigations:

- **Distinct keypairs per deployment** (no shared identity key)
- **Distinct hardware tokens per deployment** (separate YubiKeys)
- **Coordinator isolation** (per-deployment coordinator service)

## Long-term confidentiality

Archival data is encrypted under threshold KEM. PQ-secure for decades
(per `TODO.roadmap/37-long-term-archival.md`).

What survives 50+ years:

- ✅ Data encrypted under ML-KEM threshold key
- ❌ Data encrypted under RSA-2048 (breakable by quantum)
- ❌ Data signed under ECDSA P-256 (forgable by quantum — but data still
   confidential unless encrypted separately)

Confium's PQ migration path (per `TODO.roadmap/35`) ensures encryption
stays ahead of adversary capability.

## Privacy-preserving features

### Anonymous attribution

For sensitive operations, support:

- Threshold ring signatures (`confium-ring` research) — hide which T-of-N signed
- Director pseudonyms — random per-session identifier

### Differential privacy (research)

For aggregate analytics (e.g., BIML annual report), apply differential
privacy to prevent reconstruction of individual test reports.

## GDPR / data subject rights

For EU deployments:

- **Right to access**: user can request all data about them
- **Right to rectification**: incorrect data can be corrected
- **Right to erasure**: data deleted when no longer needed (BUT: threshold
  signatures and audit logs are immutable; document retention policy)
- **Data portability**: machine-readable export

Special handling: OIML deployments may have data residency requirements
(member state data must stay in member state).

## Anti-goals

- **Not** full anonymity for directors (operationally infeasible; audit trail matters)
- **Not** zero-knowledge proof of correct execution (out of scope; out of perf budget)
- **Not** blocking legitimate transparency requirements in favor of privacy

## References

- `TODO.roadmap/08-security-model.md`
- `TODO.roadmap/37-long-term-archival.md`
- [GDPR](https://gdpr.eu/)
- [NIST SP 800-188 (Data Minimization)](https://csrc.nist.gov/pubs/sp/800/188/final)
