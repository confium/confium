//! Test harness for Confium.
//!
//! Three responsibilities:
//!
//! 1. **Mock plugins** — in-repo plugins (XOR cipher, seeded RNG, etc.)
//!    used by the workspace's own test suite so it doesn't depend on the
//!    external Botan plugin.
//! 2. **Byzantine peer simulation** — for threshold-cryptography plugin
//!    testing: drop, tamper, replay, malicious-collusion behaviors.
//! 3. **NIST evaluation bench** — conformance + performance harness for
//!    MPTS candidate schemes. Deterministic environment, in-process
//!    transport, controlled RNG, vector-driven test runner.
//!
//! See `TODO.roadmap/09-nist-evaluation-harness.md` for the full design.
//!
//! Today this is a placeholder skeleton.
