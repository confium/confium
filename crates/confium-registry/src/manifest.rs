//! Typed mirrors of the TOML documents served by the registry.
//!
//! These types correspond one-to-one with the schemas documented in
//! `TODO.roadmap/06-module-registry.md`:
//!
//! - [`IndexEntry`] — one `[[plugin]]` row of the master `index.toml`.
//! - [`PluginIndex`] — the per-plugin `index.toml` (a name, latest
//!   pointer, and a list of [`VersionEntry`] rows).
//! - [`Manifest`] — the per-version `manifest.toml`, with nested
//!   [`ConfiumMeta`], [`AlgorithmMap`], and [`Artifact`] sections.
//! - [`TrustRoot`] / [`TrustRootsFile`] — the default `trust-roots.toml`
//!   served by the registry and the local override format.
//!
//! All types derive `serde::{Serialize, Deserialize}` so they can be
//! round-tripped (registry reads use `Deserialize`; the local trust store
//! and config use both). Field names match the wire (kebab-case) via
//! `serde(rename_all = "kebab-case"`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One `[[plugin]]` entry in the master `index.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexEntry {
    pub name: String,
    pub latest: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "publishers")]
    pub publishers: Vec<String>,
    #[serde(rename = "versions-url")]
    pub versions_url: String,
}

/// The parsed master `index.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryIndex {
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<IndexEntry>,
}

/// The per-plugin `index.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginIndex {
    pub name: String,
    pub latest: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "version")]
    pub versions: Vec<VersionEntry>,
}

/// One `[[version]]` entry inside a per-plugin index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionEntry {
    pub version: String,
    #[serde(rename = "manifest-url")]
    pub manifest_url: String,
}

/// A full per-version manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub plugin: ManifestPlugin,
    #[serde(default)]
    pub confium: ConfiumMeta,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub interfaces: BTreeMap<String, u32>,
    #[serde(default)]
    pub algorithms: AlgorithmMap,
    pub artifact: Artifact,
}

/// The `[plugin]` section of a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPlugin {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub homepage: String,
    #[serde(default)]
    pub source: String,
}

/// The `[confium]` runtime contract section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfiumMeta {
    #[serde(rename = "contract-version", default)]
    pub contract_version: u32,
    #[serde(rename = "min-runtime", default)]
    pub min_runtime: String,
}

/// Algorithms grouped by interface name. TOML tables whose values are
/// arrays of strings.
pub type AlgorithmMap = BTreeMap<String, Vec<String>>;

/// The `[artifact]` section of a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub mirrors: Vec<String>,
}

/// One `[[publisher]]` entry in `trust-roots.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustRoot {
    pub name: String,
    #[serde(rename = "key-id")]
    pub key_id: String,
    pub fingerprint: String,
    #[serde(rename = "key-url")]
    pub key_url: String,
}

/// The parsed `trust-roots.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustRootsFile {
    #[serde(rename = "min-signatures", default = "default_min_signatures")]
    pub min_signatures: u32,
    #[serde(default, rename = "publisher")]
    pub publishers: Vec<TrustRoot>,
}

fn default_min_signatures() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MANIFEST: &str = r#"
[plugin]
name = "botan"
version = "3.2.0"
publisher = "ribose"
license = "BSD-2-Clause"

[confium]
contract-version = 0
min-runtime = "0.3.0"

[interfaces]
hash = 0
aead = 0

[algorithms]
hash = ["SHA-256", "SHA-512"]
aead = ["AES-256-GCM"]

[artifact]
url = "https://example.com/libcfm-botan.dylib"
size = 1234
sha256 = "abcd"
mirrors = ["https://mirror.example.com/x"]
"#;

    #[test]
    fn manifest_round_trips() {
        let manifest: Manifest = toml::from_str(SAMPLE_MANIFEST).expect("parse");
        assert_eq!(manifest.plugin.name, "botan");
        assert_eq!(manifest.plugin.version, "3.2.0");
        assert_eq!(manifest.confium.contract_version, 0);
        assert_eq!(manifest.interfaces.get("hash"), Some(&0));
        assert_eq!(
            manifest.algorithms.get("hash"),
            Some(&vec!["SHA-256".to_string(), "SHA-512".to_string()])
        );
        assert_eq!(manifest.artifact.size, 1234);
        assert_eq!(manifest.artifact.mirrors.len(), 1);
    }

    #[test]
    fn registry_index_parses() {
        let src = r#"
[[plugin]]
name = "botan"
latest = "3.2.0"
description = "Botan"
publishers = ["ribose"]
versions-url = "/plugins/botan/index.toml"
"#;
        let idx: RegistryIndex = toml::from_str(src).expect("parse");
        assert_eq!(idx.plugins.len(), 1);
        assert_eq!(idx.plugins[0].name, "botan");
        assert_eq!(idx.plugins[0].publishers, vec!["ribose"]);
    }

    #[test]
    fn trust_roots_parse_with_defaults() {
        let src = r#"
[[publisher]]
name = "ribose"
key-id = "0xABCD"
fingerprint = "AAAA"
key-url = "/publishers/ribose.asc"
"#;
        let roots: TrustRootsFile = toml::from_str(src).expect("parse");
        assert_eq!(roots.min_signatures, 1);
        assert_eq!(roots.publishers[0].name, "ribose");
        assert_eq!(roots.publishers[0].key_id, "0xABCD");
    }
}
