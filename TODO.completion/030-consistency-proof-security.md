# 030 — Consistency-proof security analysis

**Category**: Security
**Severity**: High (transparency logs are meaningless without these)
**Effort**: Small (companion to 010)

## Problem

Without consistency proofs, a transparency log operator can present
two different heads to different verifiers and nobody can detect it.
This is a **structural** security problem of any append-only log that
claims to be auditable but doesn't ship consistency.

## Acceptance criteria

This doc complements [010-consistency-proofs.md](010-consistency-proofs.md)
which implements the cryptographic primitive. This doc covers:

- [ ] `docs/security/transparency-logs.md` explains:
  - **Inclusion proof**: leaf X is in tree head N.
  - **Consistency proof**: tree head N+1 extends tree head N.
  - **Threat model**: a malicious log operator's strategy without
    consistency (split-view attack).
  - **Why gossip is the second line of defense**: even with consistency
    proofs, two verifiers who never communicate can be split.
  - **Confium's deployment recommendation**: every verifier should
    gossip its latest known head to at least 2 other verifiers
    (witness network).
- [ ] A diagram of the split-view attack.
- [ ] The witness-network pattern referenced from
     `confium-transparency` gossip hooks.

## Anti-patterns

- Treating consistency as the only defense — gossip is required too.
- "Just trust the operator" — that's what the log is meant to remove.

## Related

- [010-consistency-proofs.md](010-consistency-proofs.md) — implements
  the primitive this doc explains.
- [011-ots-ers-exposure.md](011-ots-ers-exposure.md) — OTS anchoring
  is a third defense (Bitcoin-anchored tree heads).
