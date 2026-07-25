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
//! ## Status
//!
//! The deterministic environment, Byzantine transport wrapper, TOML test
//! vector parser, vector runner, JSON reporter, and criterion simulation
//! benchmark are implemented. The harness is the bench NIST MPTS uses to
//! evaluate candidate threshold schemes against a shared vector set; the
//! framework deliberately does not score or rank — it produces raw
//! measurements.

pub mod byzantine;
pub mod env;
pub mod error;
pub mod report;
pub mod result;
pub mod runner;
pub mod vector;

pub use byzantine::{BehaviorSpec, ByzantineTransport, PeerBehavior};
pub use env::{DeterministicClock, DeterministicEnv, DeterministicRng, MemoryCounter};
pub use error::Error;
pub use error::Result;
pub use report::{Report, ReportEntry};
pub use result::{Outcome, TestResult};
pub use runner::VectorRunner;
pub use vector::{ConformanceLevel, PeerBehaviorEntry, TestVector, TestVectorTest};
