#![allow(missing_docs)] // TODO: document before 1.0
//! Verifiable secret sharing, Paillier, Schnorr, and NIZK primitives.
//!
//! Standalone cryptographic primitives with no dependency on the threshold
//! session framework. Publishable to crates.io independently.

#![forbid(unsafe_code)]

pub mod nizk;
pub mod paillier;
pub mod pedersen_vss;
pub mod schnorr;
pub mod vss;

/// Experimental demonstration primitives. NOT AUDITED — known gaps
/// documented in each module; must never be used for real security.
/// Compile the `unaudited-experimental` feature to include them.
#[cfg(feature = "unaudited-experimental")]
pub mod range_proof;
#[cfg(feature = "unaudited-experimental")]
pub mod threshold_schnorr;
