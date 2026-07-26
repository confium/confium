# 54 — Performance tuning

## Performance budget

Confium must be fast enough that threshold cryptography is not a
bottleneck for real-world deployments.

| Operation | Target | Acceptable | Unacceptable |
|---|---|---|---|
| Coordinator round-trip (intra-DC) | < 10ms | < 50ms | > 200ms |
| Threshold sign (3-of-5 P-256, async) | < 5s end-to-end | < 30s | > 5min |
| Threshold sign (5-of-7 Ed25519, async) | < 3s end-to-end | < 15s | > 2min |
| Threshold encrypt (encapsulate) | < 50ms | < 200ms | > 1s |
| Threshold decrypt (3-of-5 P-256, async) | < 10s | < 60s | > 5min |
| Transparency log append | < 5ms | < 20ms | > 100ms |
| Inclusion proof verify | < 1ms | < 5ms | > 50ms |
| OTS stamp (public calendars) | 1-12 hours (async) | 1 day | > 1 week |
| Manifest parse + validate | < 10ms | < 50ms | > 200ms |

## Hot paths

### Coordinator session lifecycle

`create_session` → `submit_commitment` → `submit_share` → `aggregate` is
the hot path. Each step:

- SQLite write (WAL mode, ms range)
- Audit log append (sequential file write, μs range)
- JSON serialization for transport (μs range)

Total per session: 50-200ms coordinator CPU, plus network.

### Threshold signing (P-256)

- 1× DKG per quorum (one-time, ~1s)
- Per signature: 2 rounds, ~10ms each per party
- Aggregation: ~5ms

So a 3-of-5 P-256 signing session is 25-50ms crypto, plus async
coordination overhead.

### Threshold decryption (P-256 ElGamal)

- Encapsulate: 1ms (random + EC multiply)
- Per party partial_decrypt: 1ms
- Aggregate: ~10ms (T scalar mults + Lagrange)

Total: 5-20ms crypto per decrypt.

## Profiling

### Built-in profiling

Every coordinator session records per-phase timing in the audit log:

```json
{"event": "session_phase", "session_id": "...", "phase": "commitment_received", "duration_us": 2340}
```

Aggregatable to find slow sessions.

### Flamegraphs

`cargo flamegraph` for CPU profiling. Run on representative workload:

```sh
cargo flamegraph --bin confium-coordinator -- --benchmark workload.json
```

### Memory profiling

Use `jemalloc` (set `--features jemalloc`) for memory stats:

```sh
MALLOC_CONF=stats_print:true ./target/release/confium ...
```

## Optimization techniques

### Avoid allocation in hot paths

`Coordinator::submit_commitment` should not allocate beyond what's
strictly needed. Use `&str` instead of `String` where possible.

### Batch audit log writes

Don't `fsync` per audit entry. Batch with periodic flush (1s default).

### Pre-compute Lagrange coefficients

For repeated signing with same quorum subset, pre-compute Lagrange
coefficients once, reuse across signatures.

### Hardware acceleration

- AES-NI for AES-256-GCM (automatic via `aes-gcm` crate)
- AVX2 for SHA-256 (via `sha2` crate's asm backend)
- P-256 arithmetic uses `p256` crate's optimized implementation

### Async coordinator I/O

Tokio-based async for network I/O. SQLite uses blocking calls but
via `tokio::task::spawn_blocking` to avoid blocking the runtime.

## Known performance issues

### Async signing wall time

Biggest user-perceived latency is async signing (hours, not ms).
Mitigations:

- Shorter unlock windows for low-stakes ops
- Pre-arranged "signing time" with directors
- Push notifications via mobile app

### Coordinator availability

If coordinator goes down mid-session, sessions are preserved (SQLite
WAL) but suspended until coordinator recovers. Mitigation: redundant
coordinators (BIML operates 2-3).

## Benchmark suite

See `TODO.roadmap/44-benchmark-suite.md`. Run benchmarks in CI to catch
regressions.

## Anti-goals

- **Not** optimizing prematurely — measure first
- **Not** trading security for speed (no shortcuts on threshold property)
- **Not** using parallelism for crypto where it introduces side-channel risk

## References

- `TODO.roadmap/44-benchmark-suite.md`
- `TODO.roadmap/29-tc-coordinator-design.md`
