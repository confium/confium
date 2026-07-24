//! Local configuration (`~/.config/confium/config.toml`).
//!
//! The config file mirrors the schema documented in
//! `TODO.roadmap/07-cli-tools.md` (Configuration section). It is a
//! flat TOML document with four tables: `[registry]`, `[trust]`,
//! `[plugins]`, `[preferred]`. We keep it loose (string-keyed) rather
//! than a strict struct so `config set <dotted.key> <value>` works for
//! any key without code changes — open/closed for future additions.
//!
//! [`ConfigFile`] owns reading and writing; the CLI's `config`
//! sub-commands are thin wrappers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use confium_registry::paths::config_file;

/// The loose config document. Top-level tables map to
/// `BTreeMap<String, BTreeMap<String, Value>>` so any dotted key works.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigDocument {
    #[serde(flatten)]
    pub tables: BTreeMap<String, Table>,
}

/// One top-level table (e.g. `[registry]`).
pub type Table = BTreeMap<String, Value>;

/// A config value. TOML's value sum-type; we keep the four scalar kinds
/// the CLI's `config set` is likely to emit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Value {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<Value>),
}

impl Value {
    pub fn as_display_string(&self) -> String {
        match self {
            Value::String(s) => s.clone(),
            Value::Integer(i) => i.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Boolean(b) => b.to_string(),
            Value::Array(items) => {
                let joined: Vec<String> = items.iter().map(|v| v.as_display_string()).collect();
                format!("[{}]", joined.join(", "))
            }
        }
    }
}

/// Parse a `registry.default`-style dotted key into `(table, field)`.
///
/// Returns `Err` if the key has no `.` (we require at least
/// `table.field`).
pub fn split_dotted(key: &str) -> Result<(String, String), String> {
    let (head, tail) = key
        .split_once('.')
        .ok_or_else(|| format!("config key '{key}' must be dotted (e.g. registry.default)"))?;
    if tail.is_empty() {
        return Err(format!("config key '{key}' has empty field"));
    }
    Ok((head.to_string(), tail.to_string()))
}

/// A handle on the config file. Owns the home override so tests can
/// point at a temp dir.
pub struct ConfigFile {
    path: PathBuf,
}

impl ConfigFile {
    /// Locate the config file under the user's real home.
    pub fn user() -> Self {
        let path = config_file(None).unwrap_or_else(|_| PathBuf::from("config.toml"));
        ConfigFile { path }
    }

    /// Locate the config file under `override_home`.
    pub fn for_home(override_home: PathBuf) -> Self {
        let path =
            config_file(Some(&override_home)).unwrap_or_else(|_| PathBuf::from("config.toml"));
        ConfigFile { path }
    }

    /// The path this handle reads from / writes to.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Load the config document. If the file does not exist, returns an
    /// empty [`ConfigDocument`] (no error — fresh installs have no
    /// config yet).
    pub fn load(&self) -> std::io::Result<ConfigDocument> {
        if !self.path.exists() {
            return Ok(ConfigDocument::default());
        }
        let body = std::fs::read_to_string(&self.path)?;
        let doc: ConfigDocument = toml::from_str(&body).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("TOML parse: {e}"))
        })?;
        Ok(doc)
    }

    /// Save the config document, creating parent directories as needed.
    pub fn save(&self, doc: &ConfigDocument) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = toml::to_string_pretty(doc).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("TOML serialize: {e}"),
            )
        })?;
        std::fs::write(&self.path, body)
    }
}

/// Parse a string into a [`Value`], picking the most natural TOML kind.
///
/// - `"true"`/`"false"` → Boolean
/// - integer literal → Integer
/// - float literal → Float
/// - comma-separated `[a, b, c]` → Array
/// - otherwise → String
pub fn parse_value(raw: &str) -> Value {
    let trimmed = raw.trim();
    match trimmed {
        "true" => return Value::Boolean(true),
        "false" => return Value::Boolean(false),
        _ => {}
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let items: Vec<Value> = inner.split(',').map(|s| parse_value(s.trim())).collect();
        return Value::Array(items);
    }
    if let Ok(i) = trimmed.parse::<i64>() {
        return Value::Integer(i);
    }
    if let Ok(f) = trimmed.parse::<f64>() {
        return Value::Float(f);
    }
    Value::String(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_dotted_works() {
        assert_eq!(
            split_dotted("registry.default").unwrap(),
            ("registry".into(), "default".into())
        );
    }

    #[test]
    fn split_dotted_rejects_bare() {
        assert!(split_dotted("registry").is_err());
    }

    #[test]
    fn parse_value_recognises_kinds() {
        assert_eq!(parse_value("true"), Value::Boolean(true));
        assert_eq!(parse_value("42"), Value::Integer(42));
        // Avoid a value clippy flags as approximating PI.
        assert!(matches!(parse_value("2.5"), Value::Float(_)));
        assert_eq!(parse_value("hello"), Value::String("hello".into()));
        let arr = parse_value("[a, b, c]");
        assert!(matches!(arr, Value::Array(_)));
    }

    #[test]
    fn config_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ConfigFile::for_home(PathBuf::from(tmp.path()));
        let mut doc = ConfigDocument::default();
        doc.tables.entry("registry".into()).or_default().insert(
            "default".into(),
            Value::String("https://example.test".into()),
        );
        cfg.save(&doc).unwrap();

        let loaded = cfg.load().unwrap();
        assert_eq!(
            loaded.tables["registry"]["default"],
            Value::String("https://example.test".into())
        );
    }

    #[test]
    fn load_missing_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ConfigFile::for_home(PathBuf::from(tmp.path()));
        let doc = cfg.load().unwrap();
        assert!(doc.tables.is_empty());
    }
}
