//! Cross-crate integration tests for Confium.
//!
//! Unpublished (`publish = false`) by design: these tests exercise
//! *combinations* of crates that publish in topological order. A
//! published crate must never carry a dev-dependency on a crate that
//! publishes later — `cargo publish` resolves dev-dependencies against
//! the registry during packaging, which deadlocks the release when the
//! requirement (e.g. `^0.5.0`) is not yet published. Every cross-crate
//! test therefore lives here, where dev-deps are workspace paths and
//! never reach the registry.
