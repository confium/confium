//! Confium Store cloud KMS backends.
//!
//! This crate implements [`confium_store::backend::StoreBackend`] for the
//! three major cloud key management services:
//!
//! - **AWS Key Management Service** (feature `aws-kms`)
//! - **Google Cloud Key Management Service** (feature `gcp-kms`)
//! - **Azure Key Vault** (feature `azure-keyvault`)
//!
//! Each backend lives behind its own Cargo feature so consumers can pull
//! in only the SDK they need. With no features enabled the crate compiles
//! to nothing — it exists purely to host the three backends. See
//! `TODO.roadmap/18-hardware-keystore-backends.md` for the design.
//!
//! # Wire names
//!
//! Backends register under the wire names `"aws-kms"`, `"gcp-kms"` and
//! `"azure-keyvault"`. Pass these to `cfm_keystore_create` (or to
//! [`confium_store::Keystore::new`]) once this crate is linked into the
//! process; the link-time inventory takes care of registration.
//!
//! # KMS API status
//!
//! The SDK wiring is in place (config parsing, client construction,
//! credential lookup) but the actual KMS REST/gRPC calls are stubbed to
//! return [`confium_store::error::Error::NotImplemented`]. This lets the
//! crate ship and build across all three providers today while the
//! `cfmp_sign_with_handle` plugin contract from TODO #03 is finalised —
//! that contract governs how a signature plugin invokes a remote HSM
//! sign operation against the handle returned by `get_secret`.

pub mod backends;

// Re-export the active backend factory types so consumers can construct
// them directly without depending on the per-feature module path. Each
// alias is only present when its feature is enabled, mirroring how the
// backends are conditionally compiled.
#[cfg(feature = "aws-kms")]
pub use backends::aws_kms::AwsKmsBackend;
#[cfg(feature = "azure-keyvault")]
pub use backends::azure_keyvault::AzureKeyVaultBackend;
#[cfg(feature = "gcp-kms")]
pub use backends::gcp_kms::GcpKmsBackend;
