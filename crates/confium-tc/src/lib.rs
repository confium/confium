//! Confium threshold-cryptography primitives — the headline deliverable.
//!
//! This crate supplies:
//! - the `cfm_tc_*` FFI surface for threshold sessions
//! - session state machine (round orchestration, message routing)
//! - link-time scheme registry (in-process Rust schemes)
//!
//! Built on top of: `confium-net` (transport, separate concern),
//! `confium-store` (share persistence), `confium-api` (shared types).
//! Scheme plugins (FROST, GG18, …) implement [`registry::TcScheme`] and
//! register via [`register_tc_scheme!`]; the framework supplies
//! everything else.
//!
//! See `TODO.roadmap/04-threshold-cryptography.md` — this is the entire
//! reason Confium exists.
//!
//! ## Status
//!
//! Framework skeleton only. No TC scheme is implemented in this crate;
//! the registry + session machinery is exercised end-to-end via no-op
//! mock schemes registered in the test modules.

pub mod error;
pub mod ffi;
pub mod message;
pub mod party;
pub mod registry;
pub mod session;
pub mod share;

pub use error::Error;
pub use error::Result;
pub use message::Message;
pub use party::Party;
pub use party::PartyList;
pub use registry::RoundResult;
pub use registry::SessionImpl;
pub use registry::TcScheme;
pub use registry::TcSchemeKind;
pub use session::Session;
pub use session::SessionParams;
pub use share::Share;
