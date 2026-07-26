//! X.509 cert + scoped delegation + CMS + XMLDSig for Confium.
//!
//! Four tightly-coupled PKI concerns:
//!
//! - **X.509 cert + CSR types** with hierarchical path validation
//! - **Scoped delegation templates** (parent cert delegates bounded authority
//!   to child cert — e.g., OIML Manufacturer Model Cert → Instance Cert)
//! - **CMS (PKCS#7) SignedData envelope** verifiable by OpenSSL, Thunderbird,
//!   Adobe
//! - **XMLDSig + Exclusive C14N** for CNML-style XML documents
//!
//! Confium-produced signatures verify under standard tools (xmlsec1, openssl,
//! browser-native XMLDSig). Feature flags let consumers opt in to specific
//! envelope formats:
//!
//! - `parsing` (default): X.509 cert + CSR parsing
//! - `delegation` (default): scoped delegation templates
//! - `cms`: CMS DER encoding (`der` crate)
//! - `xmldsig`: XMLDSig + canonicalization
//!
//! See `TODO.roadmap/32-cert-delegation-cms-xmldsig.md` for the full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cert;
pub mod csr;
pub mod path;
pub mod result;

#[cfg(feature = "delegation")]
pub mod delegation;

#[cfg(feature = "cms")]
pub mod cms;

#[cfg(feature = "xmldsig")]
pub mod xmldsig;

pub use cert::*;
pub use csr::*;
pub use path::*;
pub use result::*;

#[cfg(feature = "delegation")]
pub use delegation::*;

#[cfg(feature = "cms")]
pub use cms::*;

#[cfg(feature = "xmldsig")]
pub use xmldsig::*;
