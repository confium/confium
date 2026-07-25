//! Feature-flagged cloud KMS backends.
//!
//! Each submodule is gated by its own Cargo feature so the SDK it
//! depends on is only pulled in when the consumer wants it. With no
//! features enabled this module is empty.
//!
//! Adding a new cloud provider is open/closed: create a module under
//! this directory, gate it behind a fresh feature flag in `Cargo.toml`,
//! implement [`confium_store::backend::StoreBackend`], and call
//! [`confium_store::register_backend!`]. No edit to this file is
//! required.

#[cfg(feature = "aws-kms")]
pub mod aws_kms;

#[cfg(feature = "gcp-kms")]
pub mod gcp_kms;

#[cfg(feature = "azure-keyvault")]
pub mod azure_keyvault;
