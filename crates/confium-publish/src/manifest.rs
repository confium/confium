// Generate the registry `manifest.toml` for a published plugin version.
//
// The on-disk schema is defined in `TODO.roadmap/06-module-registry.md`
// and mirrored by the example at
// `sites/registry/plugins/botan/3.2.0/manifest.toml`. This module owns
// the serde model that produces that shape and nothing else — signing,
// hashing, and directory layout live in their sibling modules
// (Open/Closed: extend the model here, change the wire shape via the
// struct, never hand-roll serialization).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::load::PluginMetadata;

/// Top-level manifest model. Field order follows the example manifest so
/// `toml::to_string_pretty` emits sections in the conventional order.
#[derive(Serialize, Debug)]
pub struct Manifest {
    pub plugin: PluginSection,
    pub confium: ConfiumSection,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub interfaces: BTreeMap<String, u8>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub algorithms: BTreeMap<String, Vec<String>>,
    pub artifact: ArtifactSection,
}

#[derive(Serialize, Debug)]
pub struct PluginSection {
    pub name: String,
    pub version: String,
    pub publisher: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct ConfiumSection {
    /// The `cfmp_interface_version` the plugin speaks (currently 0).
    #[serde(rename = "contract-version")]
    pub contract_version: u32,
    /// Minimum Confium runtime version required to load this plugin.
    #[serde(rename = "min-runtime")]
    pub min_runtime: String,
}

#[derive(Serialize, Debug)]
pub struct ArtifactSection {
    pub url: String,
    pub size: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mirrors: Vec<String>,
}

/// Inputs gathered from FFI + CLI before serialization. Building this
/// explicitly keeps `build` a pure function of its arguments.
pub struct ManifestInput<'a> {
    pub metadata: &'a PluginMetadata,
    pub publisher: &'a str,
    pub cli_name: Option<&'a str>,
    pub cli_version: Option<&'a str>,
    pub interfaces: &'a BTreeMap<String, u8>,
    pub algorithms: &'a BTreeMap<String, Vec<String>>,
    pub artifact_url: String,
    pub artifact_size: u64,
    pub artifact_sha256: String,
    pub contract_version: u32,
    pub min_runtime: &'a str,
    pub mirrors: Vec<String>,
}

/// Build a `Manifest` from resolved inputs. FFI metadata supplies
/// defaults; CLI flags override `name`/`version` when present.
pub fn build(input: &ManifestInput<'_>) -> Manifest {
    let name = input
        .cli_name
        .map(str::to_string)
        .or_else(|| input.metadata.name.clone())
        .expect("name resolved before build_manifest");
    let version = input
        .cli_version
        .map(str::to_string)
        .or_else(|| input.metadata.version.clone())
        .expect("version resolved before build_manifest");

    Manifest {
        plugin: PluginSection {
            name,
            version,
            publisher: input.publisher.to_string(),
            license: input.metadata.license.clone(),
            homepage: input.metadata.homepage.clone(),
            source: input.metadata.source_url.clone(),
        },
        confium: ConfiumSection {
            contract_version: input.contract_version,
            min_runtime: input.min_runtime.to_string(),
        },
        dependencies: BTreeMap::new(),
        interfaces: input.interfaces.clone(),
        algorithms: input.algorithms.clone(),
        artifact: ArtifactSection {
            url: input.artifact_url.clone(),
            size: input.artifact_size,
            sha256: input.artifact_sha256.clone(),
            mirrors: input.mirrors.clone(),
        },
    }
}

/// Serialize a `Manifest` to the pretty TOML string written to disk.
pub fn to_toml(manifest: &Manifest) -> Result<String, toml::ser::Error> {
    toml::to_string_pretty(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> PluginMetadata {
        PluginMetadata {
            name: Some("botan".into()),
            version: Some("3.2.0".into()),
            vendor: Some("Ribose".into()),
            license: Some("BSD-2-Clause".into()),
            homepage: Some("https://botan.randombit.net".into()),
            description: Some("Botan crypto provider".into()),
            source_url: Some("https://github.com/confium/confium-botan/tree/v3.2.0".into()),
        }
    }

    #[test]
    fn toml_contains_all_sections() {
        let meta = sample_metadata();
        let interfaces = BTreeMap::from([("hash".to_string(), 0u8)]);
        let algorithms = BTreeMap::from([("hash".to_string(), vec!["SHA-256".to_string()])]);
        let input = ManifestInput {
            metadata: &meta,
            publisher: "ribose",
            cli_name: None,
            cli_version: None,
            interfaces: &interfaces,
            algorithms: &algorithms,
            artifact_url: "https://example.com/x.dylib".into(),
            artifact_size: 1024,
            artifact_sha256: "abc123".into(),
            contract_version: 0,
            min_runtime: "0.3.0",
            mirrors: vec![],
        };
        let manifest = build(&input);
        let toml = to_toml(&manifest).unwrap();
        assert!(toml.contains("[plugin]"));
        assert!(toml.contains("[confium]"));
        assert!(toml.contains("[interfaces]"));
        assert!(toml.contains("[algorithms]"));
        assert!(toml.contains("[artifact]"));
        assert!(toml.contains("name = \"botan\""));
        assert!(toml.contains("sha256 = \"abc123\""));
    }

    #[test]
    fn cli_overrides_take_precedence() {
        let meta = sample_metadata();
        let interfaces = BTreeMap::new();
        let algorithms = BTreeMap::new();
        let input = ManifestInput {
            metadata: &meta,
            publisher: "ribose",
            cli_name: Some("my-plugin"),
            cli_version: Some("9.9.9"),
            interfaces: &interfaces,
            algorithms: &algorithms,
            artifact_url: "https://example.com/x.dylib".into(),
            artifact_size: 1024,
            artifact_sha256: "abc123".into(),
            contract_version: 0,
            min_runtime: "0.3.0",
            mirrors: vec![],
        };
        let manifest = build(&input);
        assert_eq!(manifest.plugin.name, "my-plugin");
        assert_eq!(manifest.plugin.version, "9.9.9");
    }

    #[test]
    fn empty_sections_are_skipped() {
        let meta = sample_metadata();
        let empty_ifaces = BTreeMap::new();
        let empty_algos = BTreeMap::new();
        let input = ManifestInput {
            metadata: &meta,
            publisher: "ribose",
            cli_name: None,
            cli_version: None,
            interfaces: &empty_ifaces,
            algorithms: &empty_algos,
            artifact_url: "https://example.com/x.dylib".into(),
            artifact_size: 1024,
            artifact_sha256: "abc123".into(),
            contract_version: 0,
            min_runtime: "0.3.0",
            mirrors: vec![],
        };
        let manifest = build(&input);
        let toml = to_toml(&manifest).unwrap();
        assert!(!toml.contains("[interfaces]"));
        assert!(!toml.contains("[algorithms]"));
    }
}
