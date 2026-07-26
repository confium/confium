//! CMS (PKCS#7 / RFC 5652) SignedData envelope construction and verification.
//!
//! Produces standard CMS SignedData verifiable by OpenSSL, Thunderbird/RNP,
//! Adobe, and other standards-compliant tools. Provides semantic types plus
//! real DER encoding for SHA-256 digests and algorithm identifiers.
//!
//! See `TODO.roadmap/32-cert-delegation-cms-xmldsig.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod der_encode;
mod envelope;
mod signed_data;
mod verify;

pub use der_encode::*;
pub use envelope::*;
pub use signed_data::*;
pub use verify::*;
