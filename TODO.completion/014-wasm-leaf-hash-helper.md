# 014 — WASM `compute_leaf_hash` helper

**Category**: Usability
**Severity**: Medium
**Effort**: Small (1 PR)

## Problem

`@confium/confium-wasm` exposes `verify_inclusion_with_head(leaf_entry_hash, proof, head)`
but not a helper to compute `leaf_entry_hash` from raw artifact bytes.
Consumers have to know to do `new Uint8Array([...])` of a SHA-256
themselves — error-prone.

Worse: the leaf hash isn't just `SHA-256(artifact)`. It's
`SHA-256(0x01 || entry_hash)` where `entry_hash` is itself
`SHA-256(sequence || timestamp || artifact_hash)`. So even callers who
*think* they're doing it right will produce the wrong hash.

## Acceptance criteria

- [ ] `compute_leaf_hash(sequence, timestamp_ms, artifact_bytes)` WASM
     function — returns the 32-byte Merkle leaf hash.
- [ ] `compute_artifact_hash(artifact_bytes)` WASM function — returns
     the 32-byte SHA-256 of the artifact.
- [ ] Spec: server anchors `compute_leaf_hash(seq, ts, artifact)` in a
     tree; browser re-computes the same hash and the proof verifies.
- [ ] JSDoc on both functions.

## Anti-patterns

- Hiding the algorithm behind a magic helper without docs — users
  won't trust what they can't see.
- Computing the leaf hash *inside* `verify_inclusion_with_head` —
  callers may have a pre-computed hash from elsewhere.

## Approach

Add two free functions in `confium-wasm/src/transparency.rs`. They use
the existing `hash_leaf` private helper — make it `pub(crate)` and have
the public functions call it.
