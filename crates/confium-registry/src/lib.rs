//! Client for the Confium plugin registry.
//!
//! The registry is a static-site catalog hosted at
//! `registry.confium.org` (GitHub Pages). This client fetches the
//! index, verifies publisher signatures, downloads plugin artifacts,
//! and stages them for the Engine to load.
//!
//! See `TODO.roadmap/06-module-registry.md` for the registry design,
//! including URL structure, manifest schema, trust model, and
//! publishing flow.
//!
//! # Quick start
//!
//! ```no_run
//! use confium_registry::{Registry, TrustStore, InstallOptions};
//!
//! let registry = Registry::default();
//! let trust = TrustStore::user_default()?;
//! let installed = registry.install(
//!     "botan", "3.2.0",
//!     &trust,
//!     &InstallOptions::default(),
//! )?;
//! # Ok::<(), confium_registry::Error>(())
//! ```

pub mod client;
pub mod error;
pub mod index;
pub mod install;
pub mod manifest;
pub mod trust;
pub mod verify;

pub use client::Client;
pub use error::{Error, Result};
pub use index::{CatalogEntry, MasterCatalog, PluginIndex, VersionEntry};
pub use install::{InstallOptions, InstalledPlugin, install};
pub use manifest::{ArtifactBlock, ConfiumBlock, Manifest, PluginBlock};
pub use trust::{TrustRoot, TrustStore};
pub use verify::Verification;

/// Default registry base URL.
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.confium.org";

/// A configured registry client plus trust store.
///
/// `Registry::default()` points at [`DEFAULT_REGISTRY_URL`] and the
/// user's default trust store. Construct manually to override either.
#[derive(Clone)]
pub struct Registry {
    base_url: String,
    client: Client,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_REGISTRY_URL.to_string(),
            client: Client::new(),
        }
    }
}

impl Registry {
    /// Build a registry pointed at `base_url` with a fresh HTTP client.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: Client::new(),
        }
    }

    /// Replace the HTTP client (e.g. for custom timeouts in tests).
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    /// The configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch and parse the master catalog.
    pub fn catalog(&self) -> Result<MasterCatalog> {
        let url = install::resolve_url(&self.base_url, "/index.toml")?;
        let text = self.client.get_text(&url)?;
        MasterCatalog::parse(&text)
    }

    /// Fetch and parse a per-plugin version index.
    pub fn plugin_index(&self, plugin: &str) -> Result<PluginIndex> {
        let catalog = self.catalog()?;
        let entry = catalog.find(plugin).ok_or_else(|| Error::NotFound {
            what: "plugin".to_string(),
            detail: format!("plugin '{}' is not in the master catalog", plugin),
        })?;
        let url = install::resolve_url(&self.base_url, &entry.versions_url)?;
        let text = self.client.get_text(&url)?;
        PluginIndex::parse(&text)
    }

    /// Fetch and parse a specific plugin version's manifest.
    pub fn manifest(&self, plugin: &str, version: &str) -> Result<Manifest> {
        let plugin_index = self.plugin_index(plugin)?;
        let manifest_path = plugin_index.manifest_url_for(version)?;
        let url = install::resolve_url(&self.base_url, manifest_path)?;
        let text = self.client.get_text(&url)?;
        Manifest::parse(&text)
    }

    /// Run the full install flow. See [`install::install`].
    pub fn install(
        &self,
        plugin: &str,
        version: &str,
        trust: &TrustStore,
        opts: &InstallOptions,
    ) -> Result<InstalledPlugin> {
        install::install(&self.client, &self.base_url, trust, plugin, version, opts)
    }
}
