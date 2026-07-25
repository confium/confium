//! X.509 certificate and CSR types with hierarchical path validation.
//!
//! Confium-produced certificates verify under standard tools (OpenSSL,
//! xmlsec1, browser-native). This crate provides:
//!
//! - Parsing and serialization of X.509 v3 certificates and PKCS#10 CSRs
//! - Hierarchical path validation with scope enforcement
//! - Unified verification result for composition with CNML pipeline
//!
//! See `TODO.roadmap/32-cert-delegation-cms-xmldsig.md` for the full
//! specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cert;
mod csr;
mod path;
mod result;

pub use cert::*;
pub use csr::*;
pub use path::*;
pub use result::*;
