//! OpenTimestamps client and verifier.
//!
//! Anchors hashes to the Bitcoin blockchain via public calendar servers.
//! Verifies proofs against Bitcoin block headers. Used by Confium's
//! transparency log infrastructure.
//!
//! See `TODO.roadmap/36-transparency-and-ots.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

mod client;
mod proof;

pub use client::*;
pub use proof::*;
