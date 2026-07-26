# 55 — Migration guides

## Confium version migrations

### 0.2.x → 0.3.0

The 0.3.0 release is the major architecture expansion: from 10 crates
to 53, introducing three deployment modes (Mode 1/2/3), real P-256
cryptographic implementations, and the full PKI/cert/CMS/XMLDSig
envelope stack.

**For consumers of `confium-core` (existing plugins)**:
- No API changes; existing plugins continue to work
- Re-build against `confium-core` 0.3.0 to pick up new interface support

**For consumers of `confium-tc-*`**:
- `confium-tc-frost-p256` and `confium-tc-elgamal-p256` now have real
  crypto; the previous mock interfaces are replaced
- If you depended on the mock signatures, switch to using the real APIs

**For consumers of `confium-registry`**:
- No breaking changes; new plugins appear automatically

### 0.3.x → 1.0.0 (future)

When Confium 1.0 ships:
- Public API frozen; semver commitments honored
- Migration guide published as `docs/migration/0.3-to-1.0.md`
- Deprecation cycle: 0.x features removed in 1.0 documented 6+ months ahead

## Algorithm migrations

### Ed25519 → Composite Ed25519 + ML-DSA-65

PQ migration. See `TODO.roadmap/35-pq-composite-signatures.md`.

1. Deploy new DKG with composite keypair
2. Cross-sign new public key with old Ed25519-only key
3. Issue new certs under composite key
4. Existing Ed25519 certs remain valid until expiry
5. After full migration, retire old key

### ECDSA P-256 → Composite ECDSA + ML-DSA-65

Same pattern. For OIML CNML: model certs and instance certs eventually
re-issued under composite.

### Classical → PQ-only

When ecosystem is ready (NIST guidance suggests 2030+):
1. Stop issuing classical-only signatures
2. Existing classical signatures remain verifiable
3. New signatures are PQ-only (ML-DSA-65, SLH-DSA-256)

## Quorum migrations

### Adding a new director / officer

1. Schedule rotation ceremony (sync or async per `TODO.roadmap/30`)
2. T current directors collaborate to re-share to new committee
3. New director receives encrypted share
4. Old shares (if departing) destroyed
5. Public key unchanged → all dependent certs remain valid

### Removing a director

Same protocol. Removed director's share is cryptographically invalidated.

### Changing threshold (T, N)

Same re-share protocol but with different N. E.g., expand from 5-of-7
to 7-of-9.

## Backend migrations

### Software keys → HSM

Existing software keypair → migrate to HSM:

1. Generate new keypair inside HSM
2. Issue new cert under HSM key
3. Re-sign existing artifacts under new cert (if needed)
4. Revoke old cert
5. Destroy old software key

For threshold quorums: each director migrates individually via re-share.

### HSM A → HSM B

Rare. Generate new keypair in new HSM, re-share from old to new committee.

## Deployment migrations

### Self-hosted → Cloud

Move coordinator service to cloud. Director hardware unchanged.
Public keys unchanged.

### Single coordinator → Multi-coordinator

Add second coordinator for redundancy. Directors submit to both;
aggregation requires either to succeed. Quorum keys unchanged.

## Data migrations

### Transparency log schema change

Transparency log is append-only; schema changes add new entry types,
don't modify existing. No data migration needed.

### Audit log format change

Audit log is append-only JSONL. New format = new fields in JSON objects.
Old entries still parseable (serde default fields).

## Certificate lifecycle migrations

### Old CA → New CA (root renewal)

Per `TODO.roadmap/30-tc-reshare-protocol.md` "Root renewal":
1. New DKG produces new root keypair
2. Cross-sign transition cert
3. Publish transition in transparency log
4. Grace period (e.g., 1 year) for re-issuance
5. Revoke old root

### Certificate chain deepening (root → intermediate → leaf)

Sometimes a deployment needs to add an intermediate tier. Process:
1. Generate intermediate threshold keypair
2. Sign intermediate cert under root
3. Issue future leaf certs under intermediate
4. Existing leaf certs under root remain valid until expiry

## Anti-goals

- **Not** supporting in-place algorithm upgrades without re-issuance
  (signatures are immutable; new algorithm requires new signature)
- **Not** silently migrating data formats (always explicit migration tool)
- **Not** leaving deprecated features indefinitely (scheduled removal)

## References

- `TODO.roadmap/30-tc-reshare-protocol.md`
- `TODO.roadmap/35-pq-composite-signatures.md`
- `TODO.roadmap/37-long-term-archival.md`
