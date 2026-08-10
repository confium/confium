# 38 — Property-based tests for crypto primitives

## Problem

Confium's crypto primitives had unit tests but no property-based
tests. Unit tests check one specific input → output mapping;
property tests check invariants across the entire input space
(sampled). For crypto code this catches edge cases that hand-written
tests miss: empty messages, threshold boundaries, off-by-one share
indices, etc.

## What was added

### `confium-tc-frost-p256/src/shamir.rs` — 3 proptests

- `any_t_of_n_reconstructs_secret`: for any T in [1,10], any N in
  [T,20], three different subsets of T shares all reconstruct the
  same secret. Catches "works for first T" but breaks for arbitrary
  subsets.
- `reconstruction_order_invariant`: same shares in different orders
  give the same secret. Catches accidental order-dependence in
  Lagrange interpolation.
- `below_threshold_gives_different_secret`: T-1 shares don't
  reconstruct the original secret (probability 1/2^256 of false
  positive). Catches "any subset works" bugs.

### `confium-transparency/src/merkle.rs` — 4 proptests

- `every_leaf_inclusion_proof_verifies`: for any tree size N in
  [1,100], every leaf's inclusion proof verifies against the root.
  Catches "off-by-one in the proof walk for leaf N-1" bugs.
- `inclusion_proof_rejects_wrong_entry`: a proof for entry i must
  not verify entry j (i ≠ j). Catches "any proof verifies any
  leaf" bugs.
- `append_changes_root`: appending always changes the root. Catches
  "append is silently dropped" bugs.
- `empty_tree_root_is_zero`: RFC 6962 convention that the empty
  tree hashes to all-zeros.

### `confium-composite/src/lib.rs` — 2 proptests

- `ed25519_roundtrip_json_verifies`: for any message bytes, build →
  JSON-encode → parse → verify succeeds. Catches serialization
  round-trip regressions.
- `ed25519_tamper_fails`: flipping any single bit of the message
  OR signature must cause verification to fail. Catches
  verification that ignores parts of the input.

Total: **9 new property-based tests** covering 3 crates.

## Verification

```sh
cargo test -p confium-tc-frost-p256 --lib proptests       # 3 pass
cargo test -p confium-transparency --lib proptests        # 4 pass
cargo test -p confium-composite --lib proptests           # 2 pass
cargo test --workspace                                     # all green
```

## Status

Done. 9 proptests added; full workspace tests still pass.
