//! Threshold-backed revocation service.
//!
//! Inspired by Thunderbird's IMAP-based revocation escrow, generalized
//! to T-of-N threshold authorization. Eliminates the compelled-revocation
//! risk inherent in single-party services.
//!
//! See TODO.roadmap/41-thunderbird-patterns-integration.md for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod blob;
mod service;
mod submission;

pub use blob::*;
pub use service::*;
pub use submission::*;
