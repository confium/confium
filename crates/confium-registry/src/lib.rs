#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

//! Client for the Confium plugin registry.
//!
//! The registry is a static-site catalog hosted at `registry.confium.org`
//! (GitHub Pages). This client fetches the index, verifies publisher
//! signatures, downloads plugin artifacts, and stages them for the Engine
//! to load.
//!
//! See `TODO.roadmap/06-module-registry.md` for the registry design,
//! including URL structure, manifest schema, trust model, and publishing
//! flow.
//!
//! # Crate layout
//!
//! - [`client`] — the [`Client`] that resolves plugin metadata from the
//!   static site. The transport is pluggable via the [`Fetcher`] trait so
//!   tests (and offline mirrors) can inject content without a network.
//! - [`manifest`] — typed mirrors of the TOML documents served by the
//!   registry (`index.toml`, per-plugin `index.toml`, `manifest.toml`,
//!   `trust-roots.toml`).
//! - [`install`] — install an artifact to the local plugin directory,
//!   resolving versions and (once signature verification ships) checking
//!   the trust policy.
//! - [`trust`] — the [`TrustStore`] that persists the user's trusted
//!   publishers under `~/.config/confium/trust/`.
//! - [`verify`] — cryptographic ([`verify::verify_signature`]) and
//!   policy ([`verify::check`]) layers for PGP signature verification.
//!   The crypto layer prefers in-process RNP via `libloading` and falls
//!   back to `gpg --verify` when `librnp` isn't available.

pub mod client;
pub mod error;
pub mod install;
pub mod manifest;
pub mod paths;
pub mod trust;
pub mod verify;

pub use client::{Client, Fetcher, MemoryFetcher};
pub use error::{Error, Result};
pub use install::{InstalledRecord, install};
pub use manifest::{
    AlgorithmMap, Artifact, ConfiumMeta, IndexEntry, Manifest, PluginIndex, TrustRoot,
    TrustRootsFile, VersionEntry,
};
pub use paths::{config_dir, plugin_install_dir, plugins_dir, trust_dir};
pub use trust::{TrustStore, TrustStoreEntry};
pub use verify::{Verification, verify_signature};

/// The default registry base URL.
///
/// Mirrors the canonical endpoint documented in
/// `TODO.roadmap/06-module-registry.md`. Callers can override this when
/// constructing a [`Client`] (e.g. for a mirror).
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.confium.org";
