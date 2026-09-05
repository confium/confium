# Security Policy

## Supported Versions

Confium is pre-1.0. Only the latest release line receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities by emailing the Ribose security contact at
`open.source@ribose.com`. Include:

- A description of the issue and its potential impact
- Steps to reproduce or proof of concept
- Affected versions, if known
- Suggested mitigation or fix, if any

You should receive an acknowledgement within 5 business days. Please do not
disclose the vulnerability publicly until a fix has been released.

## Security Review Process

All reports are triaged by maintainers. We may request additional information
or coordinate a joint disclosure timeline. Credit will be given in the release
notes unless you prefer to remain anonymous.

## Pre-Publication Checklist (new cryptographic primitives)

Before a new public crypto primitive lands in a `confium-crypto-*`,
`confium-privacy`, or `confium-tc-*` crate, the author answers, in the
PR description:

1. **What does `verify()` bind?** Name every public input the
   verification consumes (statement, commitment, key, message). A
   verify that binds nothing is the shipped-bug class of the 2026-09
   advisory — self-consistency is not soundness.
2. **Where does randomness come from?** Commitments must be
   randomized from the OS RNG; deterministic hashes of the secret are
   brute-force oracles.
3. **Are scalar reductions constant-fallback-free?** Nonce and
   challenge reductions use rejection sampling
   (`confium-scalar-reduce-v1` pattern) — never `unwrap_or(ZERO)`.
4. **Is there a paired rejects-forgery test?** CI enforces this
   (`scripts/check-crypto-tests.sh`); name the test in the PR.
5. **Audit-status marker present?** The crate's lib docs state
   audited/unaudited; experimental modules compile only behind
   `unaudited-experimental`.

## Supply Chain

- All dependencies are pulled from crates.io. `cargo-deny` enforces license
  and advisory gates in CI.
- Releases are published from `main` by the `release-plz` GitHub Action
  using the `CARGO_REGISTRY_TOKEN` secret. No manual publishes.
