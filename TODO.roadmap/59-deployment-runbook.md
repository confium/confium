# 59 — Deployment operations runbook

## Audience

Operators running Confium in production: BIML staff, IA officers,
enterprise Mode 2 operators.

## Daily operations

### Coordinator health check

```sh
$ confium coordinator status
Quorum: biml-root (5-of-7)
Active sessions: 2
Pending: 0
Audit log: /var/log/confium/audit.jsonl (last entry: 2026-07-25T14:32:01Z)
SQLite: /var/lib/confium/coordinator.db (12MB)
Uptime: 7d 14h 22m
```

### Audit log review

```sh
# Today's events
$ confium audit --since today

# Specific session detail
$ confium audit --session sess-0042

# All director activity for compliance review
$ confium audit --actor "biml-director-*" --last-week
```

### Transparency log status

```sh
$ confium transparency status
Tree: 47,892 entries, root: 0x3a4f...
Last OTS anchor: block 801234 (2 hours ago)
Public mirrors:
  - https://log.confium.org/oiml-cnml
  - ipfs://QmXyz...
```

## Weekly operations

### Director onboarding (rare)

1. Schedule ceremony (sync if annual, async if emergency)
2. Distribute YubiKey + initialization code
3. Director runs `confium director init` on their laptop
4. Director generates identity key on YubiKey
5. Public key registered with BIML identity CA
6. Add director to quorum via re-share

```sh
# On coordinator:
$ confium quorum reshare --quorum biml-root \
    --add biml-director-newperson \
    --reason "Annual ceremony rotation"

# On new director's laptop:
$ confium director init --yubikey-slot 9c --quorum biml-root
```

### Backup verification

```sh
# Verify SQLite backup is restorable
$ confium backup verify --file /backup/coordinator-2026-07-25.db

# Verify audit log hash chain integrity
$ confium audit verify --file /var/log/confium/audit.jsonl
```

## Monthly operations

### Proactive share refresh

```sh
$ confium quorum refresh --quorum biml-root
# All directors participate async; completes within unlock window
```

### Plugin updates

```sh
# List installed plugins
$ confium plugin list

# Check for updates
$ confium plugin update --check

# Apply update (verifies publisher signature)
$ confium plugin install confium-tc-frost-p256@0.4.1
```

### Performance review

```sh
# Generate monthly report
$ confium bench --period monthly --output report.json

# Compare against baseline
$ confium bench compare --baseline last-month --current this-month
```

## Annual operations (ceremony)

### BIML annual ceremony

Physical in-person meeting. Network-isolated room. Runbook:

1. **Pre-ceremony checklist** (1 week before):
   - Verify all directors can attend (or send proxies per protocol)
   - Test ceremony laptops offline
   - Print runbook copies for each attendee
   - Prepare replacement YubiKeys

2. **Ceremony day**:
   - Verify identity of all attendees (passport, ambassador credentials)
   - Network-isolated room (Faraday cage, no cell phones)
   - Run root renewal (if scheduled year): `confium quorum renew-root --algorithm "FROST-Ed25519+ML-DSA-65-composite"`
   - Run director rotation (if scheduled): `confium quorum reshare --sync --quorum biml-root`
   - Audit log review: previous year's sessions
   - Quorum policy review: threshold, predicate changes

3. **Post-ceremony**:
   - Publish minutes in transparency log
   - Update deployment manifest if quorum changed
   - Notify NIST MPTS evaluators if root renewed

### Ceremony documentation

Required artifacts:
- Meeting minutes (signed by all attendees)
- Cryptographic transcript (audit log of every protocol message)
- Test signature under new committee (proves re-share succeeded)
- OTS anchor of ceremony record

## Incident response procedures

### P0: Suspected key compromise

```sh
# Immediate: suspend coordinator
$ confium coordinator suspend --reason "investigating compromise"

# Emergency re-share (excludes compromised director)
$ confium quorum reshare --quorum biml-root \
    --remove "biml-director-suspect" \
    --async --reason "emergency-rotation"

# After re-share: resume coordinator
$ confium coordinator resume
```

### P1: Coordinator crash

```sh
# Check SQLite state
$ confium coordinator check-db

# Restart with WAL recovery
$ systemctl restart confium-coordinator

# Verify pending sessions resumed
$ confium coordinator status
```

### P2: Director YubiKey lost

```sh
# Director self-service: trigger emergency rotation
$ confium director report-lost --yubikey-id YK-001234

# Coordinator triggers re-share excluding that director
# New YubiKey issued at next opportunity
```

## Monitoring

### Required alerts

- Coordinator process down (>1 min)
- Audit log not written to in >5 min during business hours
- Transparency log not OTS-anchored in >2 hours
- Disk usage >80%
- Quorum quorum cannot form for >24h

### Metrics

Prometheus metrics exposed at `http://coordinator:9090/metrics`:

- `confium_sessions_active`
- `confium_sessions_completed_total`
- `confium_audit_entries_total`
- `confium_transparency_entries`
- `confium_quorum_threshold`
- `confium_quorum_participants`

## Anti-goals

- **Not** fully automating ceremony operations (human oversight required)
- **Not** exposing coordinator debug endpoints publicly
- **Not** skipping audit log integrity checks

## References

- `TODO.roadmap/53-failure-modes-and-incident-response.md`
- `TODO.roadmap/30-tc-reshare-protocol.md`
- `TODO.roadmap/54-performance-tuning.md`
