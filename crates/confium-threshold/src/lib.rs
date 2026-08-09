//! Single-entry-point crate for the Confium **Threshold** product.
//!
//! Re-exports the threshold-cryptography crates that comprise the product
//! behind feature flags. Consumers depend on `confium-threshold` instead
//! of pulling 5–12 separate crates.
//!
//! # Example
//!
//! ```toml
//! confium-threshold = { version = "0.3", features = ["cmp20", "frost-p256"] }
//! ```

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

/// Core session interface for scheme plugins.
pub use confium_tc_core as core;

#[cfg(feature = "cmp20")]
/// CMP20 threshold ECDSA over P-256.
pub use confium_tc_cmp20 as cmp20;

#[cfg(feature = "gg18")]
/// GG18 threshold ECDSA over P-256 (legacy; prefer CMP20).
pub use confium_tc_gg18 as gg18;

#[cfg(feature = "frost-p256")]
/// FROST over P-256.
pub use confium_tc_frost_p256 as frost_p256;

#[cfg(feature = "frost-ed25519")]
/// FROST over Ed25519.
pub use confium_tc_frost_ed25519 as frost_ed25519;

#[cfg(feature = "bls")]
/// Threshold BLS.
pub use confium_tc_bls as bls;

#[cfg(feature = "elgamal-p256")]
/// Threshold ElGamal encryption over P-256.
pub use confium_tc_elgamal_p256 as elgamal_p256;

#[cfg(feature = "coordinator")]
/// Multi-round orchestration coordinator.
pub use confium_coordinator as coordinator;

#[cfg(feature = "keys")]
/// Threshold key lifecycle, HSM protection, BIP-32.
pub use confium_tc_keys as keys;
