#![allow(missing_docs)] // TODO: document before 1.0
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]
//! Confium threshold-cryptography primitives — the headline deliverable.
//!
//! This crate is a **compatibility facade** that re-exports the core
//! session primitives from [`confium_tc_core`] and adds:
//!
//! - the `cfm_tc_*` FFI surface for threshold sessions
//! - async session coordinator (for globally distributed signers)
//! - share re-sharing + proactive refresh (committee evolution without
//!   changing public key)
//! - threshold KEM session interface (parallel to signing session)
//! - Paillier encryption (used by CMP20 / GG18 MtA)
//!
//! ## Migration: `confium-tc` → `confium-tc-core`
//!
//! New consumers should depend on `confium-tc-core` directly for the
//! session primitives (Session, SessionParams, Party, PartyList, Share,
//! TcScheme, etc.). The coordinator, KEM, Paillier, and reshare modules
//! are still being extracted and remain in this crate temporarily.
//!
//! See `TODO.roadmap/04-threshold-cryptography.md` — this is the entire
//! reason Confium exists.

// Re-export the identical modules from confium-tc-core. These were
// verified byte-identical (diff=0) before the facade conversion:
//   error, message, party, registry, session, share, share_envelope.
// ffi and inprocess have tc-specific concerns (unsafe, different imports)
// and remain as local modules.
pub use confium_tc_core::error;
pub use confium_tc_core::message;
pub use confium_tc_core::party;
pub use confium_tc_core::registry;
pub use confium_tc_core::session;
pub use confium_tc_core::share;
pub use confium_tc_core::share_envelope;

pub use confium_tc_core::Error;
pub use confium_tc_core::Result;
pub use confium_tc_core::Message;
pub use confium_tc_core::Party;
pub use confium_tc_core::PartyList;
pub use confium_tc_core::RoundResult;
pub use confium_tc_core::SessionImpl;
pub use confium_tc_core::TcScheme;
pub use confium_tc_core::TcSchemeKind;
pub use confium_tc_core::Session;
pub use confium_tc_core::SessionParams;
pub use confium_tc_core::Share;

// Local modules — have tc-specific concerns not yet extracted.
pub mod ffi;
pub mod inprocess;
pub mod coordinator;
pub mod kem;
pub mod paillier;
pub mod reshare;
pub mod schemes;

// The register_tc_scheme! macro is #[macro_export]'d from tc-core,
// so `confium_tc_core::register_tc_scheme!` works. Scheme crates call
// it as `confium_tc::register_tc_scheme!` — re-export for back-compat.
pub use confium_tc_core::register_tc_scheme;