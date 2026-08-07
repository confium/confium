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

// Product-surface expansions (optional adapters, off by default).
#[cfg(feature = "pkcs11-server")]
/// PKCS#11 server (drop-in HSM replacement).
pub use confium_pkcs11_server as pkcs11_server;

#[cfg(feature = "openssl-provider")]
/// OpenSSL 3.0 provider.
pub use confium_openssl_provider as openssl_provider;

#[cfg(feature = "jce-provider")]
/// Java Cryptography Extension provider.
pub use confium_jce_provider as jce_provider;

#[cfg(feature = "tls-signer")]
/// TLS 1.3 signature callback.
pub use confium_tls_signer as tls_signer;

#[cfg(feature = "composite")]
/// Composite signatures (PQ migration).
pub use confium_composite as composite;

#[cfg(feature = "attributes")]
/// Attribute-based signing predicates.
pub use confium_attributes as attributes;
