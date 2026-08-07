//! Single-entry-point crate for the Confium **Verify** product.
//!
//! Lightweight multi-language verification of composite signatures,
//! transparency proofs, and certificate chains. Verifier-only by design.
//!
//! # Example
//!
//! ```toml
//! confium-verify = { version = "0.3" }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "composite")]
/// Composite multi-algorithm signature verification.
pub use confium_composite as composite;

#[cfg(feature = "transparency")]
/// RFC 6962 transparency proof verification.
pub use confium_transparency as transparency;

#[cfg(feature = "pki")]
/// X.509 certificate + CMS verification.
pub use confium_pki as pki;

#[cfg(feature = "attributes")]
/// Attribute-based predicate evaluation.
pub use confium_attributes as attributes;

#[cfg(feature = "server")]
/// HTTP verification service.
pub use confium_verify_server as server;
