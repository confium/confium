//! Plugin manifest schema — typed metadata for Confium plugins.

use serde::{Deserialize, Serialize};

/// Semantic version components.
pub type Version = (u32, u32, u32);

/// A plugin manifest describing a Confium plugin's metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin name (kebab-case, unique in the registry).
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// Brief description.
    pub description: String,
    /// Author or organization.
    pub author: String,
    /// License identifier (SPDX).
    pub license: String,
    /// Interfaces this plugin implements.
    pub interfaces: Vec<String>,
    /// Other plugins this depends on.
    #[serde(default)]
    pub dependencies: Vec<PluginDependency>,
    /// Supported algorithms.
    #[serde(default)]
    pub algorithms: Vec<String>,
    /// Homepage URL.
    #[serde(default)]
    pub homepage: Option<String>,
}

/// A dependency on another plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    /// Dependency plugin name.
    pub name: String,
    /// Minimum required version.
    pub min_version: String,
}

/// Validation result for a manifest.
#[derive(Debug)]
pub struct ManifestValidation {
    pub valid: bool,
    pub errors: Vec<String>,
}

impl PluginManifest {
    /// Validate the manifest fields.
    pub fn validate(&self) -> ManifestValidation {
        let mut errors = Vec::new();

        if self.name.is_empty() {
            errors.push("name must not be empty".into());
        }
        if !self.name.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()) {
            errors.push("name must be kebab-case (lowercase, digits, hyphens)".into());
        }
        if self.version.is_empty() {
            errors.push("version must not be empty".into());
        } else if parse_version(&self.version).is_none() {
            errors.push(format!("version '{}' is not valid semver (X.Y.Z)", self.version));
        }
        if self.description.is_empty() {
            errors.push("description must not be empty".into());
        }
        if self.author.is_empty() {
            errors.push("author must not be empty".into());
        }
        if self.license.is_empty() {
            errors.push("license must not be empty".into());
        }
        if self.interfaces.is_empty() {
            errors.push("at least one interface must be declared".into());
        }
        for dep in &self.dependencies {
            if dep.name.is_empty() {
                errors.push("dependency name must not be empty".into());
            }
            if parse_version(&dep.min_version).is_none() {
                errors.push(format!("dependency '{}' has invalid min_version", dep.name));
            }
        }

        ManifestValidation {
            valid: errors.is_empty(),
            errors,
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Parse a "X.Y.Z" version string.
pub fn parse_version(s: &str) -> Option<Version> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts[2].parse().ok()?;
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_manifest() -> PluginManifest {
        PluginManifest {
            name: "my-hash-plugin".into(),
            version: "1.0.0".into(),
            description: "A hash plugin".into(),
            author: "Confium".into(),
            license: "BSD-2-Clause".into(),
            interfaces: vec!["hash".into()],
            dependencies: vec![],
            algorithms: vec!["SHA-256".into()],
            homepage: Some("https://confium.org".into()),
        }
    }

    #[test]
    fn valid_manifest_passes() {
        let manifest = make_valid_manifest();
        let validation = manifest.validate();
        assert!(validation.valid);
    }

    #[test]
    fn empty_name_rejected() {
        let mut m = make_valid_manifest();
        m.name = "".into();
        assert!(!m.validate().valid);
    }

    #[test]
    fn non_kebab_name_rejected() {
        let mut m = make_valid_manifest();
        m.name = "MyPlugin".into();
        assert!(!m.validate().valid);
    }

    #[test]
    fn invalid_version_rejected() {
        let mut m = make_valid_manifest();
        m.version = "1.0".into();
        assert!(!m.validate().valid);
    }

    #[test]
    fn no_interfaces_rejected() {
        let mut m = make_valid_manifest();
        m.interfaces = vec![];
        assert!(!m.validate().valid);
    }

    #[test]
    fn json_round_trip() {
        let manifest = make_valid_manifest();
        let json = manifest.to_json().unwrap();
        let recovered = PluginManifest::from_json(&json).unwrap();
        assert_eq!(recovered.name, manifest.name);
        assert_eq!(recovered.version, manifest.version);
        assert_eq!(recovered.interfaces, manifest.interfaces);
    }

    #[test]
    fn parse_version_valid() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn parse_version_invalid() {
        assert!(parse_version("1.2").is_none());
        assert!(parse_version("a.b.c").is_none());
        assert!(parse_version("").is_none());
    }

    #[test]
    fn dependency_with_bad_version_rejected() {
        let mut m = make_valid_manifest();
        m.dependencies.push(PluginDependency {
            name: "dep".into(),
            min_version: "bad".into(),
        });
        assert!(!m.validate().valid);
    }

    #[test]
    fn valid_dependency_accepted() {
        let mut m = make_valid_manifest();
        m.dependencies.push(PluginDependency {
            name: "dep-plugin".into(),
            min_version: "0.1.0".into(),
        });
        assert!(m.validate().valid);
    }
}
