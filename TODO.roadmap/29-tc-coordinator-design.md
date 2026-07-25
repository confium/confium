# 29 — Async session coordinator design

## Purpose

The coordinator service enables globally distributed threshold
signers to participate when convenient — no simultaneity required.

This is the operational backbone for institutional deployments
(BIML directors, IA officers) where sync ceremonies are infeasible
for routine operations.

## Design

### Roles

- **Coordinator** — service buffering commitments and shares;
  honest-but-curious. Cannot reconstruct secret. Sees commitments
  and shares; signs every step.
- **Signer** — director / officer app holding a threshold share.
  Submits commitments and shares when convenient.
- **Requester** — application requesting a signature. Submits
  the message to be signed; receives the final signature.

### Session lifecycle (state machine)

```
Pending           Session created by requester; awaiting signer commitments
   ↓
CommitmentsCollected   T commitments received by coordinator
   ↓
SharesCollected   T shares received by coordinator
   ↓
Completed         Signature produced, applied to artifact
   ↓
Closed            Final state, audit log complete

Or:

Expired           Unlock window elapsed before T commitments/shares
   ↓
Closed
```

### FFI sketch

```c
// Coordinator-side
uint32_t cfmc_session_create(
    Coordinator *c,
    const char *quorum_id,
    const uint8_t *message, size_t message_len,
    const char *scheme,
    uint32_t threshold_t,
    uint32_t unlock_window_seconds,
    CoordinatorSession **out);

uint32_t cfmc_session_status(
    CoordinatorSession *s,
    SessionStatus *status_out);

uint32_t cfmc_session_submit_commitment(
    CoordinatorSession *s,
    const char *signer_id,
    const uint8_t *commitment, size_t commitment_len,
    const uint8_t *signer_signature, size_t sig_len);

uint32_t cfmc_session_submit_share(
    CoordinatorSession *s,
    const char *signer_id,
    const uint8_t *share, size_t share_len,
    const uint8_t *signer_signature, size_t sig_len);

uint32_t cfmc_session_aggregate(
    CoordinatorSession *s,
    uint8_t **signature_out,
    size_t *sig_len_out);

// Signer-side
uint32_t cfms_signer_pending_sessions(
    Signer *s,
    const char *quorum_id,
    PendingSession **sessions_out,
    size_t *count_out);

uint32_t cfms_signer_submit_commitment(
    Signer *s,
    CoordinatorSession *session,
    const uint8_t *share_unlocked, size_t share_len);

uint32_t cfms_signer_submit_share(
    Signer *s,
    CoordinatorSession *session);
```

### Transport

- Signer ↔ Coordinator: WebSocket (`confium-net-ws`) for push
  notifications, or HTTP long-poll for compatibility
- Requester ↔ Coordinator: HTTP REST
- All messages signed by sender identity key

### Trust model

Coordinator sees commitments and shares but cannot:
- Reconstruct the secret key (threshold property)
- Forge commitments (director identity-key signatures)
- Forge shares (director identity-key signatures)
- Modify transcript (audit log is append-only, OTS-anchored)

Coordinator can:
- DoS the session (withhold aggregation)
- Identify which signers participated (no anonymity)

For high-stakes deployments, multiple coordinators can run in
parallel; signers submit to all; aggregation requires any
coordinator to succeed. Reduces DoS surface.

## Crate scope

### `confium-tc-coordinator` (P0)

- `Coordinator` struct owning quorum configs and active sessions
- `CoordinatorSession` state machine
- HTTP/WS server (using `axum` + `tokio-tungstenite`)
- Persistence: SQLite for session state (recoverable across restarts)
- Audit log: append-only JSONL with hash chaining
- Multi-tenant: one coordinator can serve multiple quorums

### `confium-cli` extensions

- `confium coordinator start` — run coordinator service
- `confium coordinator status` — list active sessions
- `confium coordinator session <id>` — session details

### `confium-sandbox-wasm` extensions

- WASM signer UI: list pending sessions, submit commitment/share
- Used by browser-based director/TL/manufacturer apps

## Security

- Every protocol message signed by sender identity key (non-repudiation)
- Every coordinator action logged with timestamp + director signatures
- Replay protection: each session has unique nonce; old commitments rejected
- Coordinator compromise: threshold property preserved; can DoS, cannot corrupt
- Audit log OTS-anchored periodically (transparency integration)

## Failure modes

| Scenario | Recovery |
|---|---|
| Coordinator crashes mid-session | SQLite state recovered on restart; sessions resume |
| Signer submits then goes offline | Coordinator waits; session expires after unlock window |
| Coordinator maliciously withholds aggregation | Requester can rerun with different coordinator (if multi-coordinator config) |
| Network partition | Signers queue commitments locally; submit when partition heals |

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/27-cnml-deployment.md` — BIML async signing model
- `TODO.roadmap/30-tc-reshare-protocol.md` — uses coordinator for re-sharing sessions
- FROST draft-irtf-cfrg-frost-13 § 5 (signing flow)
