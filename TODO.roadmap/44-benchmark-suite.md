# 44 — Benchmark suite

## Why benchmark

NIST MPTS evaluators need apples-to-apples performance numbers across
candidate schemes. The Confium benchmark suite is the answer.

## Performance regimes

Different performance questions for different audiences:

| Question | Audience | Tool |
|---|---|---|
| Which scheme is fastest? | NIST MPTS | Criterion + NIST vector runner |
| How does Confium scale with N? | Architects | Criterion with parametric sweeps |
| Where is time spent? | Plugin authors | `cargo flamegraph` |
| What's the memory peak? | Embedded | `cargo-proc-maps` + jemalloc |
| What's the wire overhead? | Network operators | Byte counters in benches |

## Benchmark structure

```
crates/confium-test-harness/benches/
├── bench_signing.rs          # threshold signing protocols
├── bench_encryption.rs       # threshold encryption
├── bench_dkg.rs              # DKG scaling
├── bench_reshare.rs          # share re-sharing
├── bench_merkle.rs           # transparency log
└── bench_pkcs11.rs           # Mode 2 dispatch overhead
```

## Standard workloads

### Threshold signing workload

```
For each (algorithm, T, N) ∈ {
    (FROST-ed25519, 2, 3),
    (FROST-ed25519, 3, 5),
    (FROST-ed25519, 5, 7),
    (FROST-ed25519, 7, 11),
    (CMP20-P256, 2, 3),
    (CMP20-P256, 3, 5),
    (CMP20-P256, 5, 7),
    ...
}:
    Measure:
    - DKG wall time
    - Sign wall time
    - Bytes per round
    - Peak RSS
```

### Threshold encryption workload

```
Same matrix for:
    (ElGamal-P256, 2, 3), ..., (ElGamal-P256, 5, 7)
    (ML-KEM-768-threshold, 2, 3), ..., (ML-KEM-768-threshold, 5, 7)
```

### Mode 2 dispatch overhead

```
How much slower is `confium-pkcs11-server` C_Sign()
than direct p256::ecdsa::SigningKey::sign()?
Target: < 5ms overhead for 3-of-5 quorum on localhost.
```

## CI integration

Benchmarks run on every PR that touches `crates/confium-tc-*` or
`crates/confium-pkcs11-server`:

```yaml
# .github/workflows/bench.yml
- name: Run benchmarks
  run: cargo bench --workspace
- name: Compare against main
  uses: benchmark-action/github-action-benchmark@v1
  with:
    tool: 'cargo'
    output-file-path: 'target/criterion/report.json'
    alert-threshold: '150%'
    comment-on-alert: true
```

Performance regressions >150% trigger PR comments and block merge.

## NIST submission format

The NIST MPTS portal expects:

```json
{
  "scheme": "FROST-ed25519",
  "version": "draft-irtf-cfrg-frost-13",
  "parties": 5,
  "threshold": 3,
  "iterations": 100,
  "metrics": {
    "mean_ms": 12.4,
    "p99_ms": 18.2,
    "msg_bytes": 2148,
    "peak_rss_mb": 4.2
  }
}
```

Generated automatically by `confium-bench` CLI:

```sh
$ confium-bench --scheme FROST-ed25519 --parties 5 --threshold 3 --rounds 100
# (one JSON object per scheme/iteration)
```

## Anti-goals

- **Not** optimizing prematurely — measure first
- **Not** comparing against non-threshold baselines (threshold is inherently slower)
- **Not** running benchmarks in `cargo test` (they're slow)

## References

- `TODO.roadmap/09-nist-evaluation-harness.md`
- `TODO.roadmap/42-testing-strategy.md`
