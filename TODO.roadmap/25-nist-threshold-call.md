# 25 — NIST Threshold Call response (NIST IR 8214C)

## The call is LIVE

NIST published the **First Call for Multi-Party Threshold Schemes**
on January 20, 2026 (NIST IR 8214C). MPTS 2026 workshop was
January 26-29, 2026. Submissions are being accepted.

Sources:
- https://csrc.nist.gov/projects/threshold-cryptography
- https://csrc.nist.gov/Projects/threshold-cryptography/tcall-1
- https://csrc.nist.gov/events/2026/mpts2026

## What this means for Confium

Confium's mission — bridging TC research to deployment — is now
_time-critical_. The framework is the reference implementation
platform that NIST MPTS evaluators need to:

1. Run candidate schemes against shared vectors
2. Benchmark performance apples-to-apples
3. Publish results that map directly to deployable artifacts

## Action items

### 1. FROST submission support (P0)

FROST is being actively submitted to the NIST Threshold Call.
Confium's `confium-tc-frost-ed25519` crate is a working
implementation. Action: ensure it passes the spec's official test
vectors, prepare it as a reference plugin.

### 2. Mask-FROST (new scheme)

Mask-FROST was presented at MPTS 2026 — a 2-round partially
non-interactive threshold Schnorr scheme. Add as
`crates/confium-tc-mask-frost/`.

### 3. NIST evaluation harness readiness

Ensure `confium-test-harness` can:
- Import NIST-provided vector sets (TOML format per TODO #17)
- Run candidates against shared vectors
- Produce JSON reports for NIST submission
- Benchmark wall time + message sizes + peak memory

### 4. Plugin registry: TC scheme catalog

Populate `sites/registry/` with entries for submitted schemes so
evaluators can install and test them via `confium install`.

### 5. Documentation for NIST evaluators

A dedicated "NIST Evaluator Guide" showing how to:
- Install Confium
- Install candidate scheme plugins
- Run the evaluation harness
- Submit results

## Timeline

The NIST Threshold Call has a submission window. Confium must be
ready before the deadline. Check tcall-1 documentation for the
exact date.

## Sources

- [NIST Threshold Call](https://csrc.nist.gov/projects/threshold-cryptography/tcall-1)
- [MPTS 2026 Workshop](https://csrc.nist.gov/events/2026/mpts2026)
- [FROST NIST Submission Update](https://csrc.nist.gov/presentations/2026/mpts2026-1a1)
- [Mask-FROST Presentation](https://csrc.nist.gov/presentations/2026/mpts2026-1a5)
- [MPTC Forum (Google Group)](https://groups.google.com/a/list.nist.gov/g/mptc-forum)
