# 42 — Cross-crate integration tests

## Problem

Existing integration tests are scoped to a single crate each:
CMP20 tests verify CMP20, transparency tests verify transparency,
composite tests verify composite. No test exercises the realistic
end-to-end flow of "produce a cryptographic artifact in one crate,
then prove its provenance in another."

This is the kind of integration drift that unit tests can't catch:
- A threshold signing crate changes its output format → silently
  breaks every downstream consumer that anchors signatures in
  transparency logs.
- A composite signature encoding changes → log entries that
  store composite JSON become unparseable.

## What was added

### `crates/confium-tc-cmp20/tests/cross_crate_sign_and_log.rs`

Two cross-crate tests:

1. `threshold_signature_anchors_into_transparency_log` —
   CMP20 DKG + sign → anchor the signature in a MerkleTree →
   verify the inclusion proof. Exercises both crates' public APIs
   in a realistic end-to-end flow.

2. `multiple_threshold_signatures_form_a_log` — produces 5
   threshold signatures over time, anchors each in a single log,
   verifies that every signature's inclusion proof checks against
   the cumulative root. Simulates a long-running quorum whose
   signing history is publicly auditable.

### `crates/confium-composite/tests/cross_crate_sign_and_log.rs`

One cross-crate test:

3. `composite_signature_anchors_into_transparency_log` — builds
   an Ed25519 composite, verifies it standalone, anchors its JSON
   encoding in the log, verifies the inclusion proof, then
   re-parses the anchored composite and re-verifies. Catches
   "the wire format changed but the log still references the old
   one" regressions.

## Verification

```sh
cargo test -p confium-tc-cmp20 --test cross_crate_sign_and_log
    # 2 tests pass
cargo test -p confium-composite --test cross_crate_sign_and_log
    # 1 test passes
cargo clippy --workspace --all-targets  # 0 warnings
```

## Why this matters

Cross-crate integration tests are the **only** place to catch:
- API drift between "producer" and "consumer" crates.
- Wire format incompatibilities (a struct field type changes in
  crate A; crate B's JSON deserialization silently breaks).
- Missing re-exports (a public type from crate A isn't accessible
  from crate B even though B uses it in its public API).

The 3 new tests cover the most important production flows:
threshold signing → log anchoring, and composite signing → log
anchoring. These are exactly the flows the bindings expose.

## Status

Done. 3 new cross-crate integration tests across 2 crates.
