//! TOML parsing for the master catalog (`index.toml`) and per-plugin
//! version indexes (`plugins/<name>/index.toml`).
//!
//! The on-wire shape is defined by `sites/registry/index.toml` and
//! `sites/registry/plugins/botan/index.toml`. These structs mirror it
//! one-for-one via `serde`; no hand-rolled serialization.

use crate::error::{Error, Result};
use serde::Deserialize;

/// A single entry in the master catalog.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CatalogEntry {
    pub name: String,
    pub latest: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub publishers: Vec<String>,
    #[serde(rename = "versions-url")]
    pub versions_url: String,
}

/// The master catalog: the top-level `index.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct MasterCatalog {
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<CatalogEntry>,
}

impl MasterCatalog {
    /// Parse a master catalog from TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| Error::TomlParse {
            what: "master index.toml".to_string(),
            message: Error::stringify(e),
        })
    }

    /// Look up a plugin entry by name.
    pub fn find(&self, name: &str) -> Option<&CatalogEntry> {
        self.plugins.iter().find(|p| p.name == name)
    }
}

/// A single version entry in a per-plugin index.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct VersionEntry {
    pub version: String,
    #[serde(rename = "manifest-url")]
    pub manifest_url: String,
}

/// The per-plugin version index (`plugins/<name>/index.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct PluginIndex {
    pub name: String,
    pub latest: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "version")]
    pub versions: Vec<VersionEntry>,
}

impl PluginIndex {
    /// Parse a per-plugin index from TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| Error::TomlParse {
            what: "per-plugin index.toml".to_string(),
            message: Error::stringify(e),
        })
    }

    /// Resolve a version string to its manifest URL. `"latest"` resolves
    /// to `self.latest`; an exact version string resolves to the matching
    /// [`VersionEntry`].
    pub fn manifest_url_for(&self, requested: &str) -> Result<&str> {
        let target = if requested.eq_ignore_ascii_case("latest") {
            self.latest.as_str()
        } else {
            requested
        };
        self.versions
            .iter()
            .find(|v| v.version == target)
            .map(|v| v.manifest_url.as_str())
            .ok_or_else(|| Error::NotFound {
                what: "version".to_string(),
                detail: format!("plugin '{}' has no version '{}'", self.name, target),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = include_str!("../../../sites/registry/index.toml");
    const PLUGIN: &str = include_str!("../../../sites/registry/plugins/botan/index.toml");

    #[test]
    fn parses_master_catalog() {
        let cat = MasterCatalog::parse(MASTER).expect("master parses");
        assert_eq!(cat.plugins.len(), 1);
        let botan = cat.find("botan").expect("botan present");
        assert_eq!(botan.latest, "3.2.0");
        assert_eq!(botan.publishers, vec!["ribose", "ni4"]);
        assert_eq!(botan.versions_url, "/plugins/botan/index.toml");
    }

    #[test]
    fn parses_plugin_index() {
        let idx = PluginIndex::parse(PLUGIN).expect("plugin parses");
        assert_eq!(idx.name, "botan");
        assert_eq!(idx.latest, "3.2.0");
        assert_eq!(idx.versions.len(), 1);
        assert_eq!(
            idx.versions[0].manifest_url,
            "/plugins/botan/3.2.0/manifest.toml"
        );
    }

    #[test]
    fn resolves_latest_alias() {
        let idx = PluginIndex::parse(PLUGIN).expect("plugin parses");
        let url = idx.manifest_url_for("latest").expect("latest resolves");
        assert_eq!(url, "/plugins/botan/3.2.0/manifest.toml");
    }

    #[test]
    fn resolves_exact_version() {
        let idx = PluginIndex::parse(PLUGIN).expect("plugin parses");
        let url = idx.manifest_url_for("3.2.0").expect("version resolves");
        assert_eq!(url, "/plugins/botan/3.2.0/manifest.toml");
    }

    #[test]
    fn rejects_unknown_version() {
        let idx = PluginIndex::parse(PLUGIN).expect("plugin parses");
        let err = idx.manifest_url_for("9.9.9").unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }
}
