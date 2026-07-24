//! Built-in threshold-cryptography schemes that ship with `confium-tc`.
//!
//! Real TC schemes (FROST, GG18, …) live in plugin crates. The scheme here
//! is a deterministic mock used to exercise the full session lifecycle
//! end-to-end without any real cryptographic math.

pub mod mock;

pub use mock::MockTcSigScheme;
