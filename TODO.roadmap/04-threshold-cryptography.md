# 04 — Threshold Cryptography

## Why this is the headline

Confium exists primarily to support NIST MPTS threshold-cryptography standardization (see `00-vision-and-mission.md`). The single-party crypto interfaces (`hash`, `cipher`, `aead`, `kdf`, `rng`) are supporting infrastructure for TC plugin authors, not the deliverable.

Today the codebase has zero TC support. This roadmap item describes the TC-specific design.

## What threshold cryptography needs

A threshold scheme is fundamentally a **multi-party protocol** with these characteristics:

1. **Multiple parties** (N), each holding a share of a single secret.
2. **Rounds** — parties exchange messages in synchronized rounds; output of round *k* depends on inputs of round *k-1* from all (or a threshold subset of) parties.
3. **Threshold** (T) — any T of the N parties can complete the protocol, but no T-1 coalition can.
4. **Session state** — each party maintains protocol state across rounds; the protocol is not stateless.
5. **Output** — typically a single cryptographic artifact (signature, decrypted key, distributed-key share) that's identical to what a single-party scheme would produce.

The interfaces needed:

- **tc-session** — open a session, set parameters (scheme, party-id, peer-list, threshold), hold session state
- **tc-round** — step the session forward one round; produce outgoing messages; consume incoming messages
- **tc-share** — opaque handle to a party's share of the secret
- **tc-result** — extract the final cryptographic artifact (signature, key, etc.)

## Proposed FFI

### Sessions

```c
uint32_t cfmp_tc_session_create(
    FFITcSession **out,
    const char *scheme,                 // "FROST-ed25519", "GG18-ECDSA-P256", etc.
    const CFMTcPartyList *parties,      // list of party IDs, public keys (if known)
    uint32_t threshold,                 // T
    uint32_t this_party_idx,            // which entry in `parties` is us
    const CFMTcShare *local_share,      // optional: pre-existing share
    const Option *opts);

uint32_t cfmp_tc_session_round(
    FFITcSession *s,
    const CFMTcMessage *incoming,       // messages from previous round
    uint32_t incoming_count,
    CFMTcMessage **outgoing,            // caller-allocated
    uint32_t *outgoing_count,
    uint8_t *complete,                  // 1 if the session has produced its output
    const Option *opts);

uint32_t cfmp_tc_session_result(
    FFITcSession *s,
    uint8_t *out,
    uint32_t out_max,
    uint32_t *out_len);                 // signature bytes / DKG output / etc.

uint32_t cfmp_tc_session_destroy(FFITcSession *s);
```

### Distributed Key Generation

DKG is a special case: no party enters with a complete key; they emerge with shares. Same session API, but `local_share` is null on input and a `CFMTcShare` on output.

```c
uint32_t cfmp_tc_dkg_output_share(
    FFITcSession *s,
    CFMTcShare **share_out,
    uint8_t *public_key_out,            // shared public key, identical on all parties
    uint32_t pk_max,
    uint32_t *pk_len);
```

### Auxiliary types

```c
#[repr(C)]
pub struct CFMTcPartyList {
    pub party_ids: *const *const c_char,
    pub transport_endpoints: *const *const c_char,  // "quic://node1.example.com:443"
    pub count: u32,
}

#[repr(C)]
pub struct CFMTcMessage {
    pub from_party_id: *const c_char,
    pub to_party_id: *const c_char,     // or null for broadcast
    pub round: u8,
    pub payload: *const u8,
    pub payload_len: u32,
}

#[repr(C)]
pub struct CFMTcShare {
    pub scheme: *const c_char,
    pub bytes: *const u8,
    pub len: u32,
}
```

## Built-in primitives used by TC plugins

A TC plugin internally uses other Confium interfaces:

- `rng` — for nonces, ephemeral values, DKG randomness
- `hash` — for Fiat-Shamir transcripts, commitments
- `kem` / `signature` — for authenticating peer messages (depending on the scheme)
- `network` — for exchanging round messages

Confium's value: the plugin author writes the protocol logic only. They don't implement curve math, randomness, or transport — they call Confium.

## Built-in schemes for 1.0

To make Confium credible out of the gate, the launch plugin set should include:

- **FROST (ed25519, ECDSA-P256)** — RFC draft-irtf-cfrg-frost
- **GG18 / CMP20 (ECDSA)** — widely deployed in industry
- **DKG (Pedersen, Feldman)** — for FROST and standalone

These live as separate plugin crates in `plugins/` (or as third-party plugins). Confium itself only ships the interface and the dispatch.

## Networking

TC sessions need reliable, authenticated transport between parties. See `05-networking-primitives.md` for the transport abstraction. The TC session itself is transport-agnostic: it produces bytes to send and consumes bytes received. The application (or a wrapper helper) connects session I/O to the chosen transport.

## Test harness for NIST

For NIST evaluation, every TC plugin should be runnable in a **simulation harness**:

- N parties in one process
- In-process transport (zero network)
- Deterministic RNG (so vectors are reproducible)
- Adversarial-party simulation (Byzantine, malicious-coalition)

This lives in `crates/confium-test-harness/`. See `09-nist-evaluation-harness.md`.

## Anti-goals

- Confium does not implement TC schemes itself. Plugin authors do.
- Confium does not pick which TC scheme is best. The registry is content-neutral.
- Confium does not require a specific network topology. The transport is pluggable.

## Status

- Not started. This is the headline roadmap item post-0.3.
- Depends on: `signature` (TODO #09), `kem` (TODO #10), `keyfmt` (TODO #11), `network` (#05).

## Reference

- `TODO.finalize/09-signature-interface.md` — single-party signature (foundation)
- `TODO.roadmap/05-networking-primitives.md` — transport
- `TODO.roadmap/09-nist-evaluation-harness.md` — evaluation
