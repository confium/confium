# 009 — Multi-party TC sessions

**Category**: Functional
**Severity**: High (TC framework is incomplete without it)
**Effort**: Very large (5+ PRs)

## Problem

The Ruby gem exposes FROST-P256 Shamir + ECDSA + ElGamal-P256, but the
**multi-party session orchestration** in `confium-tc::session`,
`confium-tc::coordinator`, and the per-scheme crates
(`confium-tc-frost-ed25519`, `confium-tc-cmp20`, `confium-tc-gg18`) is
not exposed. Ruby users cannot run a 3-round FROST signing ceremony
across 3 nodes.

This is the biggest single gap in the binding surface.

## Acceptance criteria

- [ ] `Confium::TC::Session` Ruby class wraps `confium_tc::Session`:
  - `.create(scheme:, threshold:, party_count:, this_party_idx:)` →
    `Session`
  - `#round` — current round number (1, 2, 3)
  - `#round_step(incoming_messages)` → `RoundResult` with
    `#outgoing_messages`, `#complete?`, `#result`
  - `#scheme_name`, `#threshold`, `#party_count`
  - `#destroy`
- [ ] `Confium::TC::Coordinator` Ruby class wraps
  `confium_tc::coordinator::Coordinator`:
  - `.new` → starts the async coordinator
  - `#create_session(session_id, params)` → registers a session
  - `#submit_commitment(session_id, party_idx, commitment_bytes)`
  - `#submit_share(session_id, party_idx, share_bytes)`
  - `#session_status(session_id)` → status hash
- [ ] 3-party FROST-ed25519 signing ceremony round-trip spec:
  - 3 local `Session` instances
  - Round 1: each generates commitments, exchanges with the others
  - Round 2: each computes shares, exchanges
  - Round 3: each combines; verifies the final signature
- [ ] Same for FROST-P256 (the existing Shamir-based signing).
- [ ] Coordinator client spec: drive a session via the async TCP
  coordinator across 3 Ruby processes.

## Anti-patterns

- Exposing the raw `Message` enum — use Ruby value objects per message
  type.
- Treating coordinator state as mutable global — coordinator should be
  an instance, not a module.

## Approach

Multi-PR breakdown (5+ PRs):

1. **PR 1**: Session interface (abstract `Session` Ruby class) + Ed25519
   FROST concrete impl.
2. **PR 2**: P256 FROST concrete impl (uses existing Shamir).
3. **PR 3**: CMP20 + GG18 concrete impls.
4. **PR 4**: Coordinator client (TCP connect + protocol messages).
5. **PR 5**: End-to-end 3-party ceremony specs.
6. **PR 6+**: WASM session API (subset — verifier-side only).

## Related

- [010-consistency-proofs.md](010-consistency-proofs.md) — TC sessions
  should anchor their outputs in a transparency log.
- [031-audit-log-exposure.md](031-audit-log-exposure.md) — every
  signing ceremony must produce an audit record.
