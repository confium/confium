//! Share re-sharing and proactive refresh protocol.
//!
//! Allows threshold committee evolution without changing the public key.
//! Director/officer rotation, proactive security refresh, emergency
//! committee changes — all preserve existing dependent certs.
//!
//! See `TODO.roadmap/30-tc-reshare-protocol.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod lagrange;
pub mod refresh;
pub mod session;

pub use lagrange::*;
pub use refresh::*;
pub use session::*;
