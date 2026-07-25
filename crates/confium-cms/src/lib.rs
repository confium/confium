//! CMS (PKCS#7 / RFC 5652) SignedData envelope construction and verification.
//!
//! Produces standard CMS SignedData verifiable by OpenSSL, Thunderbird/RNP,
//! Adobe, and other standards-compliant tools.
//!
//! See `TODO.roadmap/32-cert-delegation-cms-xmldsig.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod envelope;
mod signed_data;
mod verify;

pub use envelope::*;
pub use signed_data::*;
pub use verify::*;
