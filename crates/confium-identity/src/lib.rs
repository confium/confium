//! Actor identity management for Confium deployments.
//!
//! Each actor in a Confium deployment (manufacturer, lab, IA officer,
//! BIML director) has cryptographic identity. This crate provides:
//!
//! - Actor identity types (signing + encryption keypairs, certificate chain)
//! - Identity store abstraction (memory, persistent, hardware-backed)
//! - Hardware token descriptors (YubiKey PIV, OpenPGP card, TPM)
//! - Attribute bindings (region, expertise, role) for predicate-based signing
//!
//! See `TODO.roadmap/34-identity-and-hardware.md` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod actor;
mod attributes;
mod store;
mod token;

pub use actor::*;
pub use attributes::*;
pub use store::*;
pub use token::*;
