# 70 — End-to-end testing strategy

## Test tiers

### Tier 1: Unit tests (744+ tests)

Per-function, per-module. Fast (<1s total). Run on every PR via `ci.yml`.

### Tier 2: Integration tests

Per-crate public API. Run on every PR via `ci.yml`.

### Tier 3: Cross-crate composition

Tests that exercise multiple crates together (e.g., frost-p256 + transparency + pki). Run on every PR via `ci.yml`.

### Tier 4: E2E protocol tests (async simulated multi-node)

**Shipped**: `.github/workflows/e2e-tests.yml` + `crates/confium-tc/tests/e2e_threshold_signing.rs`

Simulates distributed signers via async tasks within a single process. Exercises:

- Real P-256 Shamir + Lagrange + ECDSA
- Coordinator session lifecycle (Pending → CommitmentsCollected → Completed)
- Async participation pattern (signers participate "when convenient")
- Threshold enforcement (3-of-5 succeeds, 2-of-5 fails)
- Duplicate submission rejection
- Audit log JSONL serialization
- Share recovery from different subsets (threshold property)
- Real ECDSA verification via `p256::ecdsa::VerifyingKey`

6 e2e tests in `e2e_threshold_signing.rs`, plus integration tests in frost-p256, transparency, and pki crates.

### Tier 5: Multi-process network e2e (future)

**Not yet shipped.** This tier would run real distributed processes communicating over real TCP:

```
┌──────────────┐     TCP/WS      ┌──────────────┐
│  Coordinator │ ←────────────── │   Signer 0   │
│   (daemon)   │ ←────────────── │   Signer 1   │
│  port 18432  │ ←────────────── │   Signer 2   │
│              │ ←────────────── │   Signer 3   │
│              │ ←────────────── │   Signer 4   │
└──────────────┘                 └──────────────┘
       ↕
┌──────────────┐
│ Test runner  │ → create session → wait → verify signature
└──────────────┘
```

#### Implementation plan

1. **CLI commands** needed:
   - `confium coordinator start --port 18432`
   - `confium signer start --coordinator 127.0.0.1:18432 --party-index N`
   - `confium quorum dkg --coordinator HOST:PORT --scheme X --threshold T --num-parties N`
   - `confium sign --coordinator HOST:PORT --message MSG --threshold T`
   - `confium verify --public-key FILE --message MSG --signature FILE`

2. **GHA workflow** structure:

```yaml
e2e-network:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Build release binaries
      run: cargo build --release -p confium-cli

    - name: Start coordinator daemon
      run: |
        ./target/release/confium coordinator start --port 18432 &
        sleep 2

    - name: Start 5 signer daemons
      run: |
        for i in $(seq 0 4); do
          ./target/release/confium signer start \
            --coordinator 127.0.0.1:18432 \
            --party-index $i &
          sleep 0.5
        done
        sleep 2

    - name: Run DKG
      run: |
        ./target/release/confium quorum dkg \
          --coordinator 127.0.0.1:18432 \
          --scheme FROST-ed25519 \
          --threshold 3 --num-parties 5

    - name: Sign message
      run: |
        ./target/release/confium sign \
          --coordinator 127.0.0.1:18432 \
          --message "e2e network test" \
          --threshold 3

    - name: Verify signature
      run: |
        ./target/release/confium verify \
          --public-key quorum.pub \
          --message "e2e network test" \
          --signature sig.bin

    - name: Stop daemons
      if: always()
      run: pkill -f confium || true
```

3. **Docker compose** for local testing:

```yaml
services:
  coordinator:
    build: .
    command: coordinator start --port 18432
    ports: ["18432:18432"]

  signer-0:
    build: .
    command: signer start --coordinator coordinator:18432 --party-index 0
    depends_on: [coordinator]

  signer-1:
    build: .
    command: signer start --coordinator coordinator:18432 --party-index 1
    depends_on: [coordinator]

  # ... signers 2-4
```

4. **Test scenarios**:

   - Full 3-of-5 signing ceremony (happy path)
   - 2-of-5 (threshold not met, graceful failure)
   - Byzantine signer (sends invalid share → identifiable abort)
   - Director rotation (re-share without changing public key)
   - Coordinator crash recovery (SQLite WAL restore)
   - Async signing (simulated time-zone delay)

#### Prerequisites

- `confium-cli` needs coordinator/signer subcommands (currently stubs)
- `confium-daemon` needs HTTP/WS server endpoint (currently skeleton)
- Real network transport via `confium-net-tcp` wired to coordinator

#### When to ship

Target: Q4 2026 (per `TODO.roadmap/68-roadmap-timeline.md` Phase 2).

The Tier 4 tests (shipped) already prove the protocol logic works. Tier 5
proves the network plumbing works. Together they give full confidence.

## Current test count

| Tier | Tests | Status |
|---|---|---|
| 1 (unit) | 744+ | ✅ Shipped |
| 2 (integration) | ~50 | ✅ Shipped |
| 3 (cross-crate) | ~30 | ✅ Shipped |
| 4 (e2e protocol) | 6 + 25 integration | ✅ Shipped (this PR) |
| 5 (network e2e) | 0 | ⏳ Future (Q4 2026) |

## Anti-goals

- **Not** requiring Docker for Tier 4 tests (single process is sufficient for protocol logic)
- **Not** running Tier 5 on every PR (slow; nightly or release-tag only)
- **Not** using mock crypto in e2e tests (real P-256, real ECDSA, real verification)

## References

- `.github/workflows/e2e-tests.yml` — Tier 4 + example smoke tests
- `crates/confium-tc/tests/e2e_threshold_signing.rs` — 6 e2e tests
- `TODO.roadmap/42-testing-strategy.md` — overall test strategy
- `TODO.roadmap/68-roadmap-timeline.md` — when Tier 5 ships
