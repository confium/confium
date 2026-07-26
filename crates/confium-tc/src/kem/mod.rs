//! Threshold KEM session interface, parallel to `confium-tc` (signing).
//!
//! Anyone can encrypt to a threshold KEM public key; T-of-N parties
//! collaborate to decrypt. This crate provides the session interface;
//! concrete algorithm implementations live in separate crates
//! (`confium-tc-elgamal-p256`, `confium-tc-ml-kem`, etc.).
//!
//! See `TODO.roadmap/31-threshold-encryption.md` for the full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod encapsulate;
mod session;
mod share;

pub use encapsulate::*;
pub use session::*;
pub use share::*;
