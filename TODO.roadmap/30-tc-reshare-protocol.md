# 30 — Share re-sharing and proactive refresh

## Purpose

Enable threshold committee evolution **without changing the public
key**. Director/officer rotation, proactive security refresh,
emergency committee changes — all preserve existing dependent certs.

This is the operational enabler for long-term institution-grade
threshold crypto. Without it, every director change forces a
re-issuance cascade.

## Two distinct operations

| Operation | What changes | Public key | When |
|---|---|---|---|
| **Re-sharing** | Committee composition (add/remove party) | **Unchanged** | Any time |
| **Proactive refresh** | All shares refreshed; committee same | **Unchanged** | Periodic (monthly/quarterly) |
| **Root renewal** | Root keypair itself | **New keypair** | Rare — algorithm migration |

This document covers re-sharing and proactive refresh. Root
renewal is in `TODO.roadmap/35-pq-composite-signatures.md`.

## Re-sharing protocol

### Setup

Current committee `C_old = {p_1, ..., p_n}` with shares `s_1, ..., s_n`,
threshold `T_old`. Aggregate secret `s = Σ s_i · λ_i(0)` (Lagrange
interpolation at origin) defines the public key `P = s · G`.

New committee `C_new = {q_1, ..., q_m}` with threshold `T_new`.

### Protocol (T-old-of-N-old directors participate)

```
Step 1: T current directors (e.g., p_1, ..., p_T) agree to re-share
Step 2: Each participating director p_i:
   For each new party q_j in C_new:
     Compute share contribution:
       s_i→j = s_i · Lagrange_basis(j evaluated at p_i's index)
   Send each s_i→j encrypted to q_j's identity key

Step 3: Each new party q_j:
   Receives T contributions s_1→j, ..., s_T→j
   Computes new share: s_j_new = Σ contributions
   Verifies new share is consistent (test signature validates
     under same public key P)

Step 4: All old shares destroyed (zeroized)
Step 5: New committee produces test signature, verifies under P
Step 6: Audit log records entire procedure, signed by all participants
```

Public key P unchanged. All dependent certs remain valid.

### FFI sketch

```c
uint32_t cfmp_reshare_session_create(
    FFITcSession **out,
    const char *scheme,
    const CFMTcPartyList *old_committee,
    const CFMTcPartyList *new_committee,
    uint32_t t_old,
    uint32_t t_new,
    const Option *opts);

uint32_t cfmp_reshare_session_round(
    FFITcSession *s,
    const CFMTcMessage *incoming, uint32_t incoming_count,
    CFMTcMessage **outgoing, uint32_t *outgoing_count,
    uint8_t *complete,
    const Option *opts);

uint32_t cfmp_reshare_session_new_share(
    FFITcSession *s,
    CFMTcShare **new_share_out);

uint32_t cfmp_reshare_session_destroy(FFITcSession *s);
```

## Proactive refresh protocol

Periodic share refresh defends against gradual compromise. An
adversary who collects T-1 shares over time still cannot sign —
each refresh invalidates previous shares.

### Protocol (Herzberg et al. 1995 pattern)

```
Step 1: Each party p_i generates random polynomial f_i(x) of degree T-1
        with f_i(0) = 0 (so sum of all f_i(0) = 0)
Step 2: Each p_i sends f_i(j) to each other party p_j (encrypted)
Step 3: Each p_j computes new share: s_j_new = s_j_old + Σ_i f_i(j)
Step 4: All old shares (s_j_old) destroyed
Step 5: Aggregate secret s = Σ s_j_new · λ_j(0) unchanged
        (because Σ f_i(0) = 0)
```

Public key unchanged. Old shares useless after refresh.

### Schedule

- Default: monthly refresh
- Configurable per quorum in manifest
- Triggered by coordinator (async, like signing sessions)

## Scheduling rotations

| Trigger | Type | Sync? |
|---|---|---|
| Director term expires | Routine | Sync (annual ceremony) |
| Director dies / resigns | Emergency | Async |
| Director YubiKey lost | Emergency | Async |
| Director compromised | Emergency | Async |
| Periodic refresh | Routine | Async |
| Quorum policy change | Routine | Sync (annual ceremony) |

## Re-sharing on the coordinator

The async coordinator (`TODO.roadmap/29-tc-coordinator-design.md`)
handles re-sharing sessions like signing sessions:

- T current directors submit re-share commitments
- Coordinator collects, broadcasts
- Each new party submits new-share confirmation
- Coordinator records in audit log

## Crate scope

### `confium-tc-reshare` (P0)

- `ReshareSession` struct managing the protocol state
- Implements both re-sharing and proactive refresh
- Algorithms: any that support Lagrange interpolation over the
  secret-sharing field (FROST, CMP20, GG18 — all compatible)
- FFI via `cfmp_reshare_*` functions

### `confium-tc` extensions

- `SessionKind` enum: `Signing | Dkg | Reshare | Refresh`
- Existing session lifecycle extended to support reshare/refresh

### `confium-cli` extensions

- `confium quorum reshare --quorum <id> --add <party> --remove <party>`
- `confium quorum refresh --quorum <id>`

## Security

- Every re-share message signed by sender identity key
- Old shares MUST be cryptographically destroyed (zeroize + audit)
- Test signature after re-share verifies new committee works
- Re-share ceremony audit-logged with all participant signatures
- Compromise window: between last refresh and current share — T-1
  collected shares in this window still cannot sign

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/29-tc-coordinator-design.md`
- [Herzberg et al., "Proactive Secret Sharing," 1995](https://www.cs.cornell.edu/people/rafael/papers/ProactiveSecretSharing.ps)
- [FROST draft-irtf-cfrg-frost-13](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/)
