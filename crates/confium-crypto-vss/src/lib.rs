#![allow(missing_docs)] // TODO: document before 1.0
//! Verifiable secret sharing, Paillier, Schnorr, and NIZK primitives.
//!
//! Standalone cryptographic primitives with no dependency on the threshold
//! session framework. Publishable to crates.io independently.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod nizk;
pub mod paillier;
pub mod pedersen_vss;
pub mod range_proof;
pub mod schnorr;
pub mod threshold_schnorr;
pub mod vss;
