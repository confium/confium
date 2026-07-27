# 011 — OTS + ERS exposure

**Category**: Functional
**Severity**: Medium (long-term archival)
**Effort**: Medium (1 PR each, 2 PRs total)

## Problem

`confium-transparency::ots` (OpenTimestamps client) and
`confium-transparency::ers` (RFC 4998 Evidence Record Syntax) exist in
the Rust crate. Neither is exposed via Ruby or WASM.

For long-term archival (decades-long), a CNML issuer needs to:

1. Anchor a Merkle root in Bitcoin via OTS.
2. Maintain an ERS archive that re-anchors as crypto ages.

## Acceptance criteria

### OTS (Ruby)

- [ ] `Confium::Transparency::OTS::Client` Ruby class:
  - `.new` → constructs the OTS client
  - `#stamp(hash_bytes)` → returns an `OTSReceipt`
  - `#verify(receipt, hash_bytes)` → bool
- [ ] `Confium::Transparency::OTS::Receipt` value object with
     `#to_bytes`, `#from_bytes`.

### ERS (Ruby)

- [ ] `Confium::Transparency::ERS::Archive` Ruby class:
  - `.new` → empty archive
  - `#add_evidence(evidence_record)` — append a renewal
  - `#verify(initial_doc_hash)` — walk the archive, verify each renewal
  - `#last_renewal_time` → Time

### WASM

- [ ] `OTS.verify(receipt_bytes, hash_bytes)` — verify-only (no
     stamping from the browser).

### Specs

- [ ] OTS round-trip against a real Bitcoin testnet stamp (mock OK).
- [ ] ERS 2-renewal archive round-trip.

## Anti-patterns

- Bundling a Bitcoin node — use the public OTS calendar servers.
- "Just SHA-256 the doc" — long-term archival requires hash agility.

## Related

- [010-consistency-proofs.md](010-consistency-proofs.md) — consistency
  feeds into archival proofs.
