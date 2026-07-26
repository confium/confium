# 53 — Failure modes and incident response

## Failure taxonomy

### Tier 1: User-facing failures (recoverable)

User can retry or fix without operator intervention.

| Failure | Cause | Recovery |
|---|---|---|
| Director unavailable | Director's laptop offline, app closed | Director opens app when convenient |
| Coordinator unreachable | Network partition, coordinator restart | Coordinator resumes; sessions resume |
| Session expired | Unlock window elapsed | Requester re-creates session |
| Invalid input | Bad cert bytes, malformed manifest | User fixes input |
| Threshold not met | Fewer than T signers responded | Wait, or lower threshold at next ceremony |

### Tier 2: Operator failures (require intervention)

Operator (BIML staff, IA staff) must take action.

| Failure | Cause | Recovery |
|---|---|---|
| Coordinator crash | Bug, OOM, hardware | Restart; SQLite state recovers |
| Audit log corruption | Disk full, hardware | Restore from backup |
| Transparency log inconsistency | Bug, split-brain coordinator | Reconcile from Bitcoin anchor + IPFS mirror |
| Quorum key compromise | Director YubiKey stolen | Emergency re-share; revoke old share |

### Tier 3: Institutional failures (require ceremony)

Require annual ceremony or emergency quorum meeting.

| Failure | Cause | Recovery |
|---|---|---|
| Root key compromise | Algorithm broken, key leak | Root renewal ceremony; cross-sign transition |
| Algorithm deprecation | SHA-1 broken, lattice weakness | Composite migration, re-quorum |
| Multiple director compromises | Coordinated attack | Mass re-share at emergency ceremony |
| Treaty withdrawal | Member state exits | Remove director; re-share |

## Incident response playbook

### P0: Active security incident (key compromise, active exploit)

1. **Detect** (automated alert or human report)
2. **Contain**:
   - For coordinator compromise: disable coordinator, switch to backup
   - For director compromise: emergency re-share excluding compromised director
   - For root compromise: schedule emergency root renewal ceremony
3. **Communicate**:
   - Notify Ribose security lead
   - Notify BIML (for OIML deployment)
   - Notify NIST MPTS evaluators if submission affected
   - Public disclosure timeline per `SECURITY.md`
4. **Recover**:
   - Patch vulnerability
   - Rotate affected keys
   - Re-issue affected certs
5. **Post-mortem**:
   - Within 7 days, written post-mortem
   - Update `SECURITY.md`, training, runbooks

### P1: Service degradation (coordinator down, network partition)

1. **Acknowledge**: post status page
2. **Mitigate**: failover to backup coordinator, restore from backup
3. **Resolve**: fix root cause
4. **Postmortem**: optional, depends on impact

### P2: Routine bug (incorrect output, UI glitch)

Standard GitHub issue → fix in next release.

## Detection

### Automated

- **Coordinator health**: `/health` endpoint returns `{"ok": true, "active_sessions": N}` every 30s
- **Audit log monitor**: alerts if no entries in N minutes during business hours
- **Transparency log monitor**: alerts if Merkle root not OTS-anchored within 1 hour
- **Plugin health**: every loaded plugin's `cfmp_finalize` + reload tested daily
- **Quorum reachability**: every quorum member polled hourly

### Manual

- **Director self-report**: "I lost my YubiKey" → trigger emergency flow
- **External disclosure**: security researcher reports issue per `SECURITY.md`

## Backup and recovery

### What's backed up

| Artifact | Frequency | Location |
|---|---|---|
| Coordinator session state (SQLite) | Continuous (WAL) | On-site + off-site replica |
| Audit log | Continuous append | Append-only, hash-chained |
| Transparency log | On every entry | Public (IPFS, Bitcoin OTS) |
| Director identity certs | On issue | Public transparency log |
| Threshold shares | On rotation | Wrapped on director laptops (NOT centrally backed up) |

### What's NOT backed up

- **Plaintext threshold shares** — only exist on director hardware
- **Director YubiKey contents** — irreplaceable; loss triggers re-share
- **Private keys of transparency log operator** — only on operator HSM

## Disaster recovery scenarios

### Coordinator data center loss

1. Spin up new coordinator in different region
2. Restore SQLite from backup
3. Resume pending sessions
4. No data loss (SQLite was WAL-replicated)

### All directors unavailable (catastrophic)

1. Transparency log + Bitcoin anchor remain verifiable
2. New directors appointed per institutional process
3. New DKG at emergency ceremony
4. New root keypair, cross-signed with old (if old root still trusted)
5. Re-issue dependent certs

### Algorithm compromise (e.g., P-256 broken)

1. Emergency ceremony: new DKG with safe algorithm (e.g., ML-DSA-65)
2. Cross-sign new root with old root (still using compromised algorithm is OK
   because the cross-sign is a one-time event)
3. Schedule dependent re-issuance
4. Eventually retire old root

## Communication templates

Pre-drafted messages for:

- Status page incident declaration
- BIML notification
- NIST notification
- Public CVE / security advisory
- Press release (for major incidents)

Templates in `docs/incident-response/templates/`.

## Anti-goals

- **Not** automated key rotation without human oversight (always requires ceremony)
- **Not** silently disabling security checks (always documented in audit log)
- **Not** "move fast and break things" — measured response for security framework

## References

- `SECURITY.md`
- `TODO.roadmap/08-security-model.md`
- `TODO.roadmap/30-tc-reshare-protocol.md`
- `TODO.roadmap/37-long-term-archival.md`
