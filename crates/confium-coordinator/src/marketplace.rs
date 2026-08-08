//! Plugin marketplace schema — discovery and registry format.

use serde::{Deserialize, Serialize};

/// Marketplace entry for a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceEntry {
    pub manifest: crate::plugin_manifest::PluginManifest,
    pub registry: RegistryInfo,
    pub install: InstallInfo,
    pub verification: VerificationInfo,
}

/// Registry-side metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryInfo {
    pub registry_name: String,
    pub published_at: chrono::DateTime<chrono::Utc>,
    pub download_count: u64,
    pub featured: bool,
}

/// Installation instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallInfo {
    pub command: String,
    pub binary_url: Option<String>,
    pub checksum_sha256: Option<String>,
}

/// Signature verification info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationInfo {
    pub signed_by: String,
    pub signature_algorithm: String,
    pub signature_hex: String,
    pub verified: bool,
}

/// Marketplace search query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query: Option<String>,
    pub interface: Option<String>,
    pub algorithm: Option<String>,
    pub min_version: Option<String>,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            query: None,
            interface: None,
            algorithm: None,
            min_version: None,
        }
    }
}

/// Match an entry against a search query.
pub fn matches(entry: &MarketplaceEntry, query: &SearchQuery) -> bool {
    if let Some(ref q) = query.query {
        let q_lower = q.to_lowercase();
        if !entry.manifest.name.to_lowercase().contains(&q_lower)
            && !entry.manifest.description.to_lowercase().contains(&q_lower)
        {
            return false;
        }
    }
    if let Some(ref iface) = query.interface {
        if !entry.manifest.interfaces.iter().any(|i| i == iface) {
            return false;
        }
    }
    if let Some(ref alg) = query.algorithm {
        if !entry.manifest.algorithms.iter().any(|a| a == alg) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_manifest::PluginManifest;

    fn make_entry(name: &str) -> MarketplaceEntry {
        MarketplaceEntry {
            manifest: PluginManifest {
                name: name.into(),
                version: "1.0.0".into(),
                description: "A test plugin".into(),
                author: "Test".into(),
                license: "MIT".into(),
                interfaces: vec!["hash".into()],
                dependencies: vec![],
                algorithms: vec!["SHA-256".into()],
                homepage: None,
            },
            registry: RegistryInfo {
                registry_name: "official".into(),
                published_at: chrono::Utc::now(),
                download_count: 100,
                featured: false,
            },
            install: InstallInfo {
                command: "confium install test".into(),
                binary_url: None,
                checksum_sha256: None,
            },
            verification: VerificationInfo {
                signed_by: "confium-bot".into(),
                signature_algorithm: "Ed25519".into(),
                signature_hex: "abc123".into(),
                verified: true,
            },
        }
    }

    #[test]
    fn entry_serializes() {
        let entry = make_entry("test");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("registry"));
    }

    #[test]
    fn search_by_name() {
        let entry = make_entry("my-hash-plugin");
        let query = SearchQuery {
            query: Some("hash".into()),
            ..Default::default()
        };
        assert!(matches(&entry, &query));
    }

    #[test]
    fn search_no_match() {
        let entry = make_entry("crypto-plugin");
        let query = SearchQuery {
            query: Some("networking".into()),
            ..Default::default()
        };
        assert!(!matches(&entry, &query));
    }

    #[test]
    fn search_by_interface() {
        let entry = make_entry("x");
        let query = SearchQuery {
            interface: Some("hash".into()),
            ..Default::default()
        };
        assert!(matches(&entry, &query));
    }

    #[test]
    fn search_by_algorithm() {
        let entry = make_entry("x");
        let query = SearchQuery {
            algorithm: Some("SHA-256".into()),
            ..Default::default()
        };
        assert!(matches(&entry, &query));
    }

    #[test]
    fn search_wrong_interface() {
        let entry = make_entry("x");
        let query = SearchQuery {
            interface: Some("aead".into()),
            ..Default::default()
        };
        assert!(!matches(&entry, &query));
    }

    #[test]
    fn empty_query_matches_all() {
        let entry = make_entry("anything");
        assert!(matches(&entry, &SearchQuery::default()));
    }

    #[test]
    fn combined_filters() {
        let entry = make_entry("hash-plugin");
        let query = SearchQuery {
            query: Some("hash".into()),
            interface: Some("hash".into()),
            ..Default::default()
        };
        assert!(matches(&entry, &query));
    }
}
