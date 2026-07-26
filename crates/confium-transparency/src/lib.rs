//! Append-only Merkle tree transparency log with OTS anchoring.
//!
//! Every artifact (cert, signature, revocation, re-share event) is
//! appended to a Merkle tree. Tree roots are periodically anchored to
//! Bitcoin via OpenTimestamps. Verifiers can prove any artifact was in
//! the publicly-visible tree as of a given Bitcoin block.
//!
//! See `TODO.roadmap/36-transparency-and-ots.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod entry;
pub mod merkle;
pub mod proof;

pub use entry::*;
pub use merkle::*;
pub use proof::*;
