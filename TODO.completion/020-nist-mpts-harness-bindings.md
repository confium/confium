# 020 — NIST MPTS harness bindings

**Category**: Audience
**Severity**: Medium (NIST is a partnership, not just a user)
**Effort**: Medium (1 PR — Python + Ruby wrappers)

## Problem

`confium-test-harness` (the NIST MPTS evaluation bench) is Rust-only.
NIST evaluators and academics typically work in Python or Ruby. They
need a way to drive the harness from those languages without writing
Rust.

## Acceptance criteria

- [ ] `Confium::MPTS::Harness` Ruby class wraps the Rust test harness:
  - `.new(scheme:, vector_set:)` — pick a TC scheme + NIST vector set
  - `#run` — executes the vector set, returns `MPTSResult`
  - `#benchmark(iterations:)` — performance benchmark
- [ ] Result exposes `#pass_rate`, `#failures`, `#timing_ms`.
- [ ] Python equivalent via a thin ctypes/CFFI wrapper around the C
     ABI (already exists from `confium-core`).
- [ ] Spec: run a known-good NIST PQC vector set, confirm 100% pass.

## Anti-patterns

- Hand-rolling benchmarking logic — use the existing `criterion`-based
  bench in the Rust crate.
- Coupling this to NIST's specific test rig — keep the binding generic
  over vector sets.

## Approach

Wire `confium-test-harness` public functions through magnus (Ruby) +
ctypes (Python). The Rust crate already has clean entry points.

## Related

- [009-multi-party-tc-sessions.md](009-multi-party-tc-sessions.md) —
  harness exercises the session API.
- [023-test-vector-verification.md](023-test-vector-verification.md) —
  broader test-vector coverage.
