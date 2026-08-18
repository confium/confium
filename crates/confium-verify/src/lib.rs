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
#![allow(missing_docs)] // TODO: document before 1.0

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

#[cfg(feature = "signatif")]
/// The SIGNATIF framework layer: trust graph, co-signed artifacts,
/// verification pipeline, coverage reports, registries.
pub use confium_signatif as signatif;

#[cfg(feature = "server")]
/// HTTP verification service.
#[allow(rustdoc::broken_intra_doc_links)]
pub use confium_verify_server as server;
