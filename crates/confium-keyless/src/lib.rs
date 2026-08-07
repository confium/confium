//! Single-entry-point crate for the Confium **Keyless** product.
//!
//! OIDC-based keyless threshold signing for short-lived certificates.
//!
//! # Example
//!
//! ```toml
//! confium-keyless = { version = "0.3" }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "oidc")]
/// OIDC JWT verification + claim validation.
pub use confium_oidc as oidc;

#[cfg(feature = "threshold")]
/// Threshold signing surface used to issue short-lived certs.
pub use confium_threshold as threshold;

#[cfg(feature = "verify")]
/// Composite signature verification for keyless artifacts.
pub use confium_composite as composite;
