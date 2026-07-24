//! Registry client.
//!
//! The [`Client`] resolves plugin metadata from the static-site catalog.
//! Network access is abstracted behind the [`Fetcher`] trait so:
//!
//! - production builds can plug in `reqwest`/`ureq` (or read from a
//!   mirrored checkout), and
//! - tests inject a [`MemoryFetcher`] holding the TOML documents
//!   verbatim, with no network.
//!
//! The client only reads structured TOML; the actual artifact download
//! (the `[artifact]` URL in a manifest) is handled by [`crate::install`].

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::manifest::{Manifest, PluginIndex, RegistryIndex, TrustRootsFile};

/// Default path components inside the registry site.
const INDEX_PATH: &str = "/index.toml";
const TRUST_ROOTS_PATH: &str = "/trust-roots.toml";

/// Pluggable transport for registry content.
///
/// Implementations return the raw bytes for a given registry-relative
/// path (e.g. `/plugins/botan/index.toml`). The default production
/// implementation will join these against the registry base URL and
/// perform an HTTP GET; tests use [`MemoryFetcher`].
pub trait Fetcher {
    fn fetch(&self, path: &str) -> Result<Vec<u8>>;
}

/// An in-memory [`Fetcher`] keyed by registry-relative path.
///
/// Built via [`MemoryFetcher::new`] with the registry root URL, then
/// populated with [`MemoryFetcher::with`]. Missing paths surface as
/// [`Error::NotFound`].
#[derive(Default, Clone)]
pub struct MemoryFetcher {
    base_url: String,
    docs: HashMap<String, Vec<u8>>,
}

impl MemoryFetcher {
    /// Create an empty fetcher bound to `base_url` (only used for display).
    pub fn new(base_url: impl Into<String>) -> Self {
        MemoryFetcher {
            base_url: base_url.into(),
            docs: HashMap::new(),
        }
    }

    /// Return the base URL this fetcher is anchored to.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Insert a document at `path` (registry-relative, e.g.
    /// `/plugins/botan/index.toml`).
    pub fn with(mut self, path: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        self.docs.insert(path.into(), body.into());
        self
    }
}

impl Fetcher for MemoryFetcher {
    fn fetch(&self, path: &str) -> Result<Vec<u8>> {
        self.docs.get(path).cloned().ok_or_else(|| Error::NotFound {
            path: path.to_string(),
        })
    }
}

/// A client bound to a registry base URL and a [`Fetcher`].
///
/// Construct with [`Client::new`] (default fetcher is a `MemoryFetcher`,
/// intended for tests — production code supplies a real HTTP fetcher).
pub struct Client<F: Fetcher = MemoryFetcher> {
    base_url: String,
    fetcher: F,
}

impl Client<MemoryFetcher> {
    /// Build a client backed by a [`MemoryFetcher`]. Production code
    /// should use [`Client::with_fetcher`] to plug in a network-capable
    /// transport.
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into();
        Client {
            base_url: base_url.clone(),
            fetcher: MemoryFetcher::new(base_url),
        }
    }
}

impl<F: Fetcher> Client<F> {
    /// Build a client with a custom fetcher.
    pub fn with_fetcher(base_url: impl Into<String>, fetcher: F) -> Self {
        Client {
            base_url: base_url.into(),
            fetcher,
        }
    }

    /// Borrow the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch the master catalog.
    pub fn index(&self) -> Result<RegistryIndex> {
        let body = self.fetch(INDEX_PATH)?;
        self.parse(INDEX_PATH, &body)
    }

    /// Fetch the default trust roots file.
    pub fn trust_roots(&self) -> Result<TrustRootsFile> {
        let body = self.fetch(TRUST_ROOTS_PATH)?;
        self.parse(TRUST_ROOTS_PATH, &body)
    }

    /// Fetch a per-plugin version index.
    ///
    /// `versions_url` is the registry-relative path from the master
    /// index entry (e.g. `/plugins/botan/index.toml`).
    pub fn plugin_index(&self, versions_url: &str) -> Result<PluginIndex> {
        let body = self.fetch(versions_url)?;
        self.parse(versions_url, &body)
    }

    /// Fetch a per-version manifest.
    pub fn manifest(&self, manifest_url: &str) -> Result<Manifest> {
        let body = self.fetch(manifest_url)?;
        self.parse(manifest_url, &body)
    }

    /// Resolve a `(name, version)` to a manifest.
    ///
    /// When `version` is `None`, the per-plugin `latest` pointer is used.
    pub fn resolve(&self, name: &str, version: Option<&str>) -> Result<Manifest> {
        let index = self.index()?;
        let entry = index
            .plugins
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| Error::PluginNotFound {
                name: name.to_string(),
            })?;
        let plugin_index = self.plugin_index(&entry.versions_url)?;
        let target_version = match version {
            Some(v) => v.to_string(),
            None => plugin_index.latest.clone(),
        };
        let version_entry = plugin_index
            .versions
            .iter()
            .find(|v| v.version == target_version)
            .ok_or_else(|| Error::VersionNotFound {
                name: name.to_string(),
                version: target_version.clone(),
            })?;
        self.manifest(&version_entry.manifest_url)
    }

    /// Fetch raw bytes for `path` via the configured [`Fetcher`].
    fn fetch(&self, path: &str) -> Result<Vec<u8>> {
        self.fetcher.fetch(path)
    }

    fn parse<T>(&self, path: &str, body: &[u8]) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let src = std::str::from_utf8(body).map_err(|e| Error::Fetch {
            path: path.to_string(),
            message: format!("invalid UTF-8: {e}"),
        })?;
        toml::from_str(src).map_err(|e| Error::TomlParse {
            path: path.to_string(),
            source: e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fetcher() -> MemoryFetcher {
        MemoryFetcher::new("https://example.test")
            .with(
                INDEX_PATH,
                r#"
[[plugin]]
name = "botan"
latest = "3.2.0"
description = "Botan"
publishers = ["ribose"]
versions-url = "/plugins/botan/index.toml"
"#,
            )
            .with(
                "/plugins/botan/index.toml",
                r#"
name = "botan"
latest = "3.2.0"
description = "Botan"

[[version]]
version = "3.2.0"
manifest-url = "/plugins/botan/3.2.0/manifest.toml"
"#,
            )
            .with(
                "/plugins/botan/3.2.0/manifest.toml",
                r#"
[plugin]
name = "botan"
version = "3.2.0"
publisher = "ribose"

[artifact]
url = "https://example.test/x.so"
size = 10
sha256 = "abcd"
"#,
            )
    }

    #[test]
    fn client_resolves_latest() {
        let client = Client::with_fetcher("https://example.test", sample_fetcher());
        let manifest = client.resolve("botan", None).expect("resolve");
        assert_eq!(manifest.plugin.name, "botan");
        assert_eq!(manifest.plugin.version, "3.2.0");
    }

    #[test]
    fn client_resolves_pinned_version() {
        let client = Client::with_fetcher("https://example.test", sample_fetcher());
        let manifest = client
            .resolve("botan", Some("3.2.0"))
            .expect("resolve pinned");
        assert_eq!(manifest.plugin.version, "3.2.0");
    }

    #[test]
    fn missing_plugin_errors() {
        let client = Client::with_fetcher("https://example.test", sample_fetcher());
        let err = client.resolve("ghost", None).unwrap_err();
        assert!(matches!(
            err,
            Error::PluginNotFound { ref name } if name == "ghost"
        ));
    }

    #[test]
    fn missing_version_errors() {
        let client = Client::with_fetcher("https://example.test", sample_fetcher());
        let err = client.resolve("botan", Some("9.9.9")).unwrap_err();
        assert!(matches!(
            err,
            Error::VersionNotFound { ref name, ref version }
                if name == "botan" && version == "9.9.9"
        ));
    }
}
