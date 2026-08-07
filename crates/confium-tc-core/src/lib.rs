//! Confium threshold cryptography core — the minimal session interface.
//!
//! This crate provides the irreducible primitives that threshold scheme
//! plugins (CMP20, FROST, GG18) compile against.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod message;
pub mod party;
pub mod registry;
pub mod schemes;
pub mod session;
pub mod share;
pub mod share_adapter;
pub mod share_envelope;

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
