//! Threshold KEM session interface, parallel to `confium-tc` (signing).
//!
//! Anyone can encrypt to a threshold KEM public key; T-of-N parties
//! collaborate to decrypt. This crate provides the session interface;
//! concrete algorithm implementations live in separate crates
//! (`confium-tc-elgamal-p256`, `confium-tc-ml-kem`, etc.).
//!
//! See `TODO.roadmap/31-threshold-encryption.md` for the full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod encapsulate;
pub mod session;
pub mod share;

pub use encapsulate::*;
pub use session::*;
pub use share::*;
