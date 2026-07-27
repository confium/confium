# 010 — Transparency consistency proofs (RFC 6962 §2.1.2)

**Category**: Functional
**Severity**: High (transparency logs are meaningless without these)
**Effort**: Medium (1 PR Rust + 1 PR Ruby + 1 PR WASM = 3 PRs)

## Problem

`Confium::Transparency::MerkleTree` exposes inclusion proofs ("leaf X
is in tree head N") but not **consistency proofs** ("tree head N+1
extends tree head N"). Without consistency proofs, a malicious log
operator can present different heads to different verifiers, and nobody
can detect it.

This is the difference between an *append-only log* and an
*auditable log*.

## Acceptance criteria

- [ ] `confium-transparency::merkle::MerkleTree::consistency_proof(old_size, new_size)`
     returns `Result<ConsistencyProof, MerkleError>`.
- [ ] `ConsistencyProof` is a list of (hash, side) pairs.
- [ ] `verify_consistency(old_head, new_head, proof)` standalone fn
     returns `Result<(), MerkleError>`.
- [ ] `Confium::Transparency::MerkleTree#consistency_proof(old_size, new_size)`
     in Ruby.
- [ ] `Confium::Transparency.verify_consistency(old_head, new_head, proof)`
     standalone Ruby module function.
- [ ] WASM `verify_consistency_with_heads(old_head_json, new_head_json, proof_json)`
     function.
- [ ] Spec: append 10 leaves, get consistency proof from size 5 → 10,
     verify. Then tamper with new_head → verification fails.
- [ ] Spec: consistency proof for size 0 → N works (initial root).

## Anti-patterns

- Treating consistency as just "recompute root and compare" — defeats
  the purpose (client would need every leaf).
- Allowing `old_size > new_size` — that's a different operation.

## Approach

Implement RFC 6962 §2.1.2 algorithm:

1. Compute the sub-tree shape for `[0, old_size)` and `[0, new_size)`.
2. Walk the paths from each size down to their shared ancestor.
3. Emit the hashes along the way.

Verification: walk the same shape client-side and check that the
recomputed root matches `new_head` AND that the implicit old root
matches `old_head`.

## Related

- [030-consistency-proof-security.md](030-consistency-proof-security.md) —
  the security analysis of why this matters.
