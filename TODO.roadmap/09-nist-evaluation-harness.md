# 09 — NIST Evaluation Harness

## Why NIST needs this

NIST MPTS evaluates candidate threshold schemes against common criteria: correctness, performance, side-channel resistance, Byzantine-fault tolerance, interoperability. Without a shared harness, evaluators must re-implement each scheme from scratch just to measure it.

Confium's value: if every candidate has a Confium plugin exposing the same `tc-signature` / `tc-kem` interface, NIST can:

1. Run identical workloads across candidates.
2. Compare apples-to-apples on performance, memory, message sizes.
3. Run Byzantine fault simulations deterministically.
4. Publish vectors that any future implementation can be tested against.

## What the harness provides

`crates/confium-test-harness/` contains:

### Deterministic environment

- **In-process transport** — no real network, all parties in one process
- **Mock RNG** — seeded deterministic random stream per party; reproducible across runs
- **Controlled clock** — for timeout-sensitive protocols
- **Memory accounting** — track per-party allocation for benchmarking

### Test vector format

```toml
# test-vectors/frost-ed25519/v1.toml
[scheme]
name = "FROST-ed25519"
version = "draft-irtf-cfrg-frost-13"

[test]
parties = 5
threshold = 3
message = "hello world"               # or hex for binary
seed = "0xdeadbeef..."                # for deterministic RNG
expected_signature_hex = "..."        # final signature output

[[peer_behavior]]
party_id = "alice"
type = "honest"

[[peer_behavior]]
party_id = "bob"
type = "honest"

[[peer_behavior]]
party_id = "eve"
type = "byzantine-drop"               # drops round-2 messages
```

### Test categories

1. **Correctness** — does the protocol produce a valid signature for the given input?
2. **Threshold** — does it succeed with exactly T honest parties?
3. **Byzantine detection** — does it detect misbehaving peers?
4. **Reproducibility** — do the same inputs always produce the same outputs?
5. **Interop** — can party A from plugin X talk to party B from plugin Y?
6. **Performance** — wall time, message bytes, rounds, peak memory.

### Byzantine peer simulation

Mock peer behaviors:

- `byzantine-drop` — drop all messages from one round
- `byzantine-malicious` — send crafted invalid messages to try to corrupt the protocol
- `byzantine-collusion` — N-1 peers collude against one (testing the threshold T+1 case)
- `byzantine-replay` — replay old messages to try to confuse the protocol
- `byzantine-tamper` — flip bits in transit

Each scheme's plugin is expected to:
- Either complete successfully (the scheme tolerates the behavior)
- Or abort with a proof of misbehavior (signed evidence identifying the bad peer)

### Performance benchmarks

`crates/confium-test-harness/benches/`:

- `bench_signing.rs` — sign N messages with a threshold signing scheme
- `bench_dkg.rs` — measure DKG wall time vs N
- `bench_round_trip.rs` — latency per round message
- `bench_message_size.rs` — total bytes on the wire per protocol execution

Benchmarks use `criterion` (BSD-3-Clause, already in our license allowlist). Outputs `target/criterion/` reports, uploaded as CI artifacts.

### Comparison reports

A CLI tool `confium-bench` runs the harness across all installed plugins and produces a comparison report:

```
$ confium-bench --scheme tc-signature-ed25519 --parties 5 --threshold 3 --rounds 100

Scheme: FROST-ed25519 (5 parties, T=3, 100 iterations)

Plugin              Mean (ms)   P99 (ms)    Msg bytes  Peak RSS (MB)
frost-cfrg          12.4        18.2        2,148      4.2
tss-rust            14.8        22.1        2,896      5.1
academia-impl       89.3        112.7       8,234      12.8
```

## CI integration

The harness runs in CI on every plugin PR:

```yaml
# .github/workflows/eval.yml
- name: Run NIST eval harness
  uses: confium/eval-action@v1
  with:
    plugin-artifact: ${{ github.workspace }}/target/release/libcfm-plugin.so
    vectors: tests/vectors/
```

Results are posted as PR comments and as machine-readable JSON in the run output.

## NIST publication pipeline

NIST evaluators can:

1. Install candidate plugins via `confium install <candidate>@<version>`.
2. Run the harness with the official NIST vector set.
3. Submit the JSON output to NIST's MCTS portal.

The harness IS the official conformance test bench. Confium itself doesn't certify; it provides the bench.

## Status

- Not started.
- Depends on: TC interface (#04), mock RNG (#17 TODO.finalize/08), in-process transport (#05).

## Anti-goals

- Confium does not assign scores. The harness produces raw measurements; NIST decides what they mean.
- Confium does not pick winners. All candidate schemes are eligible to publish plugins.
- Confium does not gate the registry on harness pass-rate. That would make Confium a gatekeeper for NIST, which is politically untenable and technically brittle.

## Reference

- `TODO.roadmap/04-threshold-cryptography.md` — what the harness exercises
- `TODO.roadmap/05-networking-primitives.md` — in-process transport
- `TODO.roadmap/00-vision-and-mission.md` — why this matters for NIST
