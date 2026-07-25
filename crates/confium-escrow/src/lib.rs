//! Threshold key escrow and recovery orchestration.
//!
//! Inspired by Thunderbird's revocation escrow and key backup designs,
//! generalized to T-of-N threshold cryptography. A user's key is
//! encrypted to a threshold public key; recovery requires T-of-N
//! custodians to participate in an async decryption ceremony.
//!
//! See TODO.roadmap/41-thunderbird-patterns-integration.md for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod blob;
mod metadata;
mod service;

pub use blob::*;
pub use metadata::*;
pub use service::*;
