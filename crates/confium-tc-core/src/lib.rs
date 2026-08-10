//! Confium threshold cryptography core — the minimal session interface.
//!
//! This crate provides the irreducible primitives that threshold scheme
//! plugins (CMP20, FROST, GG18) compile against.

#![deny(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

pub mod commitment;
pub mod error;
pub mod error_codes;
pub mod message;
pub mod nonce;
pub mod party;
pub mod registry;
pub mod schemes;
pub mod session;
pub mod share;
pub mod share_adapter;
pub mod share_envelope;
pub mod unified_error;

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
