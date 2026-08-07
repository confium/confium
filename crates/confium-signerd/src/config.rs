//! Signer daemon configuration.
//!
//! Loaded from a TOML file specified via `--config`.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Coordinator TCP address (e.g., "127.0.0.1:18432").
    pub coordinator_addr: String,
    /// This signer's identity.
    pub signer_id: String,
    /// Quorum this signer belongs to.
    pub quorum_id: String,
    /// Path to the local share file (JSON).
    pub share_file: String,
    /// Signing scheme (e.g., "CMP20", "FROST-P256").
    pub scheme: String,
    /// Reconnect backoff in seconds (default: 5).
    #[serde(default = "default_backoff")]
    pub reconnect_backoff_secs: u64,
    /// Maximum reconnect attempts before giving up (0 = infinite).
    #[serde(default = "default_max_retries")]
    pub max_reconnect_attempts: u32,
}

fn default_backoff() -> u64 {
    5
}

fn default_max_retries() -> u32 {
    0
}

impl DaemonConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.display().to_string(), e.to_string()))?;
        let config: Self = toml::from_str(&contents)
            .map_err(|e| ConfigError::Parse(path.display().to_string(), e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.signer_id.is_empty() {
            return Err(ConfigError::Invalid("signer_id must not be empty".into()));
        }
        if self.quorum_id.is_empty() {
            return Err(ConfigError::Invalid("quorum_id must not be empty".into()));
        }
        if self.coordinator_addr.is_empty() {
            return Err(ConfigError::Invalid("coordinator_addr must not be empty".into()));
        }
        Ok(())
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {0}: {1}")]
    Read(String, String),
    #[error("failed to parse {0}: {1}")]
    Parse(String, String),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn valid_config_parses() {
        let toml_str = r#"
coordinator_addr = "127.0.0.1:18432"
signer_id = "director-1"
quorum_id = "biml-root"
share_file = "/etc/confium/director-1.json"
scheme = "CMP20"
"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(toml_str.as_bytes()).unwrap();
        let config = DaemonConfig::load(tmp.path()).unwrap();
        assert_eq!(config.signer_id, "director-1");
        assert_eq!(config.quorum_id, "biml-root");
        assert_eq!(config.scheme, "CMP20");
        assert_eq!(config.reconnect_backoff_secs, 5);
    }

    #[test]
    fn empty_signer_id_rejected() {
        let toml_str = r#"
coordinator_addr = "127.0.0.1:18432"
signer_id = ""
quorum_id = "q"
share_file = "/tmp/share.json"
scheme = "CMP20"
"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(toml_str.as_bytes()).unwrap();
        assert!(DaemonConfig::load(tmp.path()).is_err());
    }

    #[test]
    fn custom_backoff_parses() {
        let toml_str = r#"
coordinator_addr = "127.0.0.1:18432"
signer_id = "s1"
quorum_id = "q"
share_file = "/tmp/share.json"
scheme = "CMP20"
reconnect_backoff_secs = 30
max_reconnect_attempts = 10
"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(toml_str.as_bytes()).unwrap();
        let config = DaemonConfig::load(tmp.path()).unwrap();
        assert_eq!(config.reconnect_backoff_secs, 30);
        assert_eq!(config.max_reconnect_attempts, 10);
    }
}
