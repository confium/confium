//! Async session coordinator for distributed threshold signing.
//!
//! The coordinator service enables globally distributed threshold
//! signers to participate when convenient — no simultaneity required.
//!
//! This crate provides the session state machine, commitment/share
//! buffering, audit logging, and a real TCP server + client for
//! network communication.
//!
//! See `TODO.roadmap/29-tc-coordinator-design.md` for the full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod client;
pub mod coordinator;
pub mod net;
pub mod net_server;
pub mod session;

pub use audit::*;
pub use coordinator::*;
pub use session::*;
