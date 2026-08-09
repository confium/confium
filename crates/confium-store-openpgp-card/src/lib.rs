//! OpenPGP card backend (YubiKey OpenPGP applet, Nitrokey, Gnuk).
//!
//! Standards-only: uses the OpenPGP card v3+ spec. No vendor-specific
//! SDKs. All OpenPGP-compatible smartcards work.
//!
//! The OpenPGP card spec natively supports:
//! - SIG slot (signing)
//! - DEC slot (decryption)
//! - AUT slot (authentication)
//!
//! Real hardware integration requires `openpgp-card` + `card-backend-pcsc`
//! crates, which depend on PCSC. This crate provides the trait interface
//! and an in-memory mock backend for testing.
//!
//! See `TODO.roadmap/34-identity-and-hardware.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

mod backend;
mod rnp_backend;
mod slot;

pub use backend::*;
pub use rnp_backend::*;
pub use slot::*;
