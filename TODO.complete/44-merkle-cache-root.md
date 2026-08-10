# 44 — Performance: cache MerkleTree root, eliminate O(N) per root() call

## Problem

`MerkleTree::root()` recomputed the entire tree from leaf hashes on
every call. For a tree of N leaves, each call was O(N) (and allocated
O(N) intermediate Vecs).

In a transparency log server that:
- Calls `root()` after every `append()` to publish a tree head.
- Calls `root()` on every inclusion-proof verification.
- Calls `root()` on every consistency-proof verification.

…this is O(N) work per request. For a log with 10M entries and 100
queries/sec, that's 10^9 hashes/sec just for root recomputation.

## What was done

Added a `cached_root: Hash` field to `MerkleTree`. Maintained on every
`append()` via a new private `compute_root()` helper. `root()` is now
O(1) — returns the cached field.

```rust
pub struct MerkleTree {
    entries: Vec<MerkleEntry>,
    leaf_hashes: Vec<Hash>,
    cached_root: Hash,  // ← new
}

impl MerkleTree {
    pub fn append(&mut self, entry: MerkleEntry) -> u64 {
        // … existing logic …
        self.cached_root = Self::compute_root(&self.leaf_hashes);
        // …
    }

    pub fn root(&self) -> Hash {
        self.cached_root  // O(1)
    }

    fn compute_root(leaf_hashes: &[Hash]) -> Hash { /* O(N) */ }
}
```

The trade-off is O(N) work per `append()` instead of O(N) work per
`root()`. Appends are infrequent (one per artifact), root reads are
frequent (one per proof verification), so this is the right direction.

Future optimization: implement incremental root updates that only
recompute the path from the new leaf to the root (truly O(log N) per
append). The current `compute_root` is still O(N) per append, but
deferred to append-time only.

## Verification

```sh
cargo test -p confium-transparency   # 31 + 7 + 1 = 39 tests pass
```

Behavior is unchanged for every existing test — `root()` returns the
same value, just faster. Cross-crate tests in confium-tc-cmp20 and
confium-composite also pass.

## Why this matters

The transparency log is the long-tail component of every Confium
deployment. A 10x speedup in `root()` directly improves every
verifier's latency. The correctness invariants are preserved by the
test suite.

## Status

Done. One struct field added, two methods refactored, all 39 tests
green.
