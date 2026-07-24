//! TOML parsing for per-version plugin manifests
//! (`plugins/<name>/<version>/manifest.toml`).
//!
//! The on-wire shape mirrors `sites/registry/plugins/botan/3.2.0/manifest.toml`
//! one-for-one via serde. Optional tables (dependencies, interfaces,
//! algorithms) default to empty so manifests that omit them still parse.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

/// The `[plugin]` block: identity, license, links.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PluginBlock {
    pub name: String,
    pub version: String,
    pub publisher: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub homepage: String,
    #[serde(default)]
    pub source: String,
}

/// The `[confium]` block: runtime compatibility.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct ConfiumBlock {
    #[serde(rename = "contract-version")]
    pub contract_version: u32,
    #[serde(rename = "min-runtime", default)]
    pub min_runtime: String,
}

/// The `[artifact]` block: where to download and how to verify.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ArtifactBlock {
    pub url: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub mirrors: Vec<String>,
}

/// A complete per-version manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub plugin: PluginBlock,
    #[serde(default)]
    pub confium: ConfiumBlock,
    /// `[dependencies]` — a flat map of plugin-name → version-range string.
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    /// `[interfaces]` — interface-name → interface-version.
    #[serde(default)]
    pub interfaces: BTreeMap<String, u32>,
    /// `[algorithms]` — interface-name → list of algorithm identifiers.
    #[serde(default)]
    pub algorithms: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub artifact: Option<ArtifactBlock>,
}

impl Manifest {
    /// Parse a manifest from TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| Error::TomlParse {
            what: "manifest.toml".to_string(),
            message: Error::stringify(e),
        })
    }

    /// The artifact block, or an error if the manifest omitted it.
    pub fn require_artifact(&self) -> Result<&ArtifactBlock> {
        self.artifact.as_ref().ok_or_else(|| Error::MissingField {
            what: "manifest.toml".to_string(),
            field: "artifact".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str =
        include_str!("../../../sites/registry/plugins/botan/3.2.0/manifest.toml");

    #[test]
    fn parses_botan_manifest() {
        let m = Manifest::parse(MANIFEST).expect("manifest parses");
        assert_eq!(m.plugin.name, "botan");
        assert_eq!(m.plugin.version, "3.2.0");
        assert_eq!(m.plugin.publisher, "ribose");
        assert_eq!(m.plugin.license, "BSD-2-Clause");
        assert_eq!(m.confium.contract_version, 0);
        assert_eq!(m.confium.min_runtime, "0.3.0");

        // Interfaces and algorithms survive the round trip.
        assert_eq!(m.interfaces.get("hash"), Some(&0));
        assert_eq!(m.interfaces.get("aead"), Some(&0));
        assert_eq!(
            m.algorithms.get("hash"),
            Some(&vec![
                "SHA-256".to_string(),
                "SHA-384".to_string(),
                "SHA-512".to_string(),
                "SHA3-256".to_string(),
                "SHA3-512".to_string(),
            ])
        );

        let art = m.require_artifact().expect("artifact present");
        assert_eq!(art.size, 1_234_567);
        assert!(!art.url.is_empty());
        assert_eq!(art.mirrors.len(), 1);
    }

    #[test]
    fn defaults_optional_blocks() {
        let minimal = r#"
[plugin]
name = "x"
version = "0.1.0"
publisher = "ribose"
"#;
        let m = Manifest::parse(minimal).expect("minimal parses");
        assert!(m.dependencies.is_empty());
        assert!(m.interfaces.is_empty());
        assert!(m.algorithms.is_empty());
        assert!(m.artifact.is_none());
        assert!(m.require_artifact().is_err());
    }
}
