use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub deployment: DeploymentHeader,
    #[serde(default)]
    pub mode: DeploymentMode,
    #[serde(default)]
    pub tiers: Vec<Tier>,
    #[serde(default)]
    pub transparency: TransparencyConfig,
    #[serde(default)]
    pub async_signing: AsyncSigningConfig,
    #[serde(default)]
    pub archival: ArchivalConfig,
    #[serde(default)]
    pub quorums: Vec<Quorum>,
    #[serde(default)]
    pub pkcs11_server: Option<Pkcs11ServerConfig>,
    #[serde(default)]
    pub pqc_migration: Option<PqcMigrationPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentHeader {
    pub name: String,
    pub operator: String,
    #[serde(default)]
    pub charter_url: Option<String>,
    pub manifest_version: u32,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    PeerToPeer,
    Pkcs11Replacement,
    #[default]
    CertificatePki,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier {
    pub name: String,
    pub role: String,
    pub signing_algorithm: String,
    #[serde(default)]
    pub encryption_algorithm: Option<String>,
    pub threshold: Threshold,
    #[serde(default)]
    pub delegated_by: Option<String>,
    #[serde(default)]
    pub delegation_scope: Option<String>,
    #[serde(default)]
    pub ceremony: Option<Ceremony>,
    #[serde(default)]
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Threshold {
    pub t: u32,
    pub n: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ceremony {
    pub sync_required: bool,
    #[serde(default)]
    pub frequency: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransparencyConfig {
    #[serde(default)]
    pub log_operator: Option<String>,
    #[serde(default)]
    pub anchors: Vec<String>,
    #[serde(default)]
    pub gossip: bool,
    #[serde(default)]
    pub public_mirror_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncSigningConfig {
    #[serde(default = "default_unlock_window")]
    pub default_unlock_window_minutes: u32,
    #[serde(default)]
    pub coordinator_operator: Option<String>,
}

fn default_unlock_window() -> u32 {
    240
}

impl Default for AsyncSigningConfig {
    fn default() -> Self {
        Self {
            default_unlock_window_minutes: default_unlock_window(),
            coordinator_operator: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchivalConfig {
    #[serde(default = "default_renewal_period")]
    pub renewal_period_years: u32,
    #[serde(default)]
    pub re_sign_under: Option<String>,
}

fn default_renewal_period() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quorum {
    pub name: String,
    pub threshold: Threshold,
    pub coordinator: String,
    #[serde(default)]
    pub share_storage_backend: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11ServerConfig {
    pub slot_count: u32,
    pub default_signing_algorithm: String,
    pub default_threshold: Threshold,
    pub share_storage: String,
    pub hsm_module: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PqcMigrationPlan {
    #[serde(default)]
    pub current: Option<String>,
    #[serde(default)]
    pub target_2027: Option<String>,
    #[serde(default)]
    pub target_2029: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest TOML parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("manifest TOML serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("manifest validation failed: {0}")]
    Validation(String),
}

pub fn parse_manifest(toml_str: &str) -> Result<Manifest, ManifestError> {
    let manifest: Manifest = toml::from_str(toml_str)?;
    Ok(manifest)
}

pub fn manifest_to_toml(manifest: &Manifest) -> Result<String, ManifestError> {
    Ok(toml::to_string_pretty(manifest)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_mode3_manifest() {
        let toml_str = r#"
[deployment]
name = "Test Deployment"
operator = "Test Operator"
manifest_version = 1
mode = "certificate_pki"

[[tiers]]
name = "root"
role = "root"
signing_algorithm = "FROST-ed25519"
threshold = { t = 3, n = 5 }
"#;
        let manifest = parse_manifest(toml_str).expect("parse");
        assert_eq!(manifest.deployment.name, "Test Deployment");
        assert_eq!(manifest.mode, DeploymentMode::CertificatePki);
        assert_eq!(manifest.tiers.len(), 1);
        assert_eq!(manifest.tiers[0].threshold.t, 3);
        assert_eq!(manifest.tiers[0].threshold.n, 5);
    }

    #[test]
    fn parses_mode2_manifest_with_pkcs11_server() {
        let toml_str = r#"
mode = "pkcs11_replacement"

[deployment]
name = "Enterprise PKI"
operator = "Acme Corp"
manifest_version = 1

[pkcs11_server]
slot_count = 8
default_signing_algorithm = "FROST-P256"
default_threshold = { t = 3, n = 5 }
share_storage = "pkcs11-wrap"
hsm_module = "/usr/lib/pkcs11/yubihsm.so"
"#;
        let manifest = parse_manifest(toml_str).expect("parse");
        assert_eq!(manifest.mode, DeploymentMode::Pkcs11Replacement);
        let pkcs11 = manifest.pkcs11_server.expect("pkcs11_server");
        assert_eq!(pkcs11.slot_count, 8);
    }

    #[test]
    fn round_trips_manifest_through_toml() {
        let toml_str = r#"
[deployment]
name = "Round Trip"
operator = "Op"
manifest_version = 1

[transparency]
anchors = ["bitcoin-ots"]
gossip = false

[async_signing]
default_unlock_window_minutes = 120
"#;
        let manifest = parse_manifest(toml_str).expect("parse");
        let reserialized = manifest_to_toml(&manifest).expect("serialize");
        let reparsed = parse_manifest(&reserialized).expect("reparse");
        assert_eq!(manifest.deployment.name, reparsed.deployment.name);
        assert_eq!(
            manifest.async_signing.default_unlock_window_minutes,
            reparsed.async_signing.default_unlock_window_minutes
        );
    }
}
