//! Local trust-root store.
//!
//! The trust store persists user-accepted publisher trust roots under
//! `~/.config/confium/trust/<publisher>.json`. Each record carries the
//! publisher name, its key fingerprint, and the key material URL.
//!
//! All writes are confined to the configured trust directory. Publisher
//! names are validated to reject path-traversal (`..`, absolute paths,
//! separators) before any filesystem operation.

use crate::error::{Error, InvalidPublisherNameSnafu, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One accepted trust root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustRoot {
    pub name: String,
    #[serde(default)]
    pub key_id: String,
    pub fingerprint: String,
    #[serde(default)]
    pub key_url: String,
}

/// A local on-disk trust store. Cheap to clone (just a path).
#[derive(Clone)]
pub struct TrustStore {
    dir: PathBuf,
}

impl TrustStore {
    /// Open the trust store rooted at `dir`, creating the directory if
    /// missing.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        if !dir.exists() {
            map_io(std::fs::create_dir_all(&dir), &dir)?;
        }
        Ok(Self { dir })
    }

    /// Open the default user trust store at
    /// `~/.config/confium/trust/`.
    pub fn user_default() -> Result<Self> {
        let base = dirs::config_dir().ok_or_else(|| Error::Io {
            path: "<config dir>".to_string(),
            message: "no user config directory available on this platform".to_string(),
        })?;
        Self::open(base.join("confium").join("trust"))
    }

    /// Path to the record file for `name`. Validates `name` first to
    /// reject path traversal.
    fn path_for(&self, name: &str) -> Result<PathBuf> {
        validate_publisher_name(name)?;
        Ok(self.dir.join(format!("{}.json", name)))
    }

    /// Insert or replace the trust root for `root.name`.
    pub fn put(&self, root: &TrustRoot) -> Result<()> {
        let path = self.path_for(&root.name)?;
        let json = serde_json::to_string_pretty(root).map_err(|e| Error::Io {
            path: path.display().to_string(),
            message: format!("serialize trust root: {}", e),
        })?;
        std::fs::write(&path, json).map_err(|e| Error::Io {
            path: path.display().to_string(),
            message: Error::stringify(e),
        })?;
        Ok(())
    }

    /// Read the trust root for `name`, if present.
    pub fn get(&self, name: &str) -> Result<Option<TrustRoot>> {
        let path = self.path_for(name)?;
        if !path.exists() {
            return Ok(None);
        }
        let text = map_io(std::fs::read_to_string(&path), &path)?;
        let root: TrustRoot = serde_json::from_str(&text).map_err(|e| Error::Io {
            path: path.display().to_string(),
            message: format!("deserialize trust root: {}", e),
        })?;
        Ok(Some(root))
    }

    /// Remove the trust root for `name`. Returns `false` if no record
    /// existed.
    pub fn remove(&self, name: &str) -> Result<bool> {
        let path = self.path_for(name)?;
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path).map_err(|e| Error::Io {
            path: path.display().to_string(),
            message: Error::stringify(e),
        })?;
        Ok(true)
    }

    /// List every trusted publisher name present in the store.
    pub fn list(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let entries = map_io(std::fs::read_dir(&self.dir), &self.dir)?;
        for entry in entries {
            let entry = map_io(entry, &self.dir)?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    /// True iff `publisher` is present in the store.
    pub fn is_trusted(&self, publisher: &str) -> Result<bool> {
        Ok(self.get(publisher)?.is_some())
    }
}

/// Reject publisher/plugin names that could escape the store directory.
///
/// Names must be non-empty, ASCII lowercase letters/digits/hyphens, and
/// must not contain path separators, `..`, or a leading hyphen.
pub(crate) fn validate_publisher_name(name: &str) -> Result<()> {
    validate_identifier(name, "publisher")
}

/// Reject plugin names with the same rules as publisher names.
pub(crate) fn validate_plugin_name(name: &str) -> Result<()> {
    validate_identifier(name, "plugin")
}

fn validate_identifier(name: &str, kind: &str) -> Result<()> {
    let ok = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    let valid = !name.is_empty()
        && !name.starts_with('-')
        && name != ".."
        && name != "."
        && name.chars().all(ok);
    if valid {
        Ok(())
    } else {
        InvalidPublisherNameSnafu {
            name,
            reason: format!(
                "invalid {} name: must be lowercase ASCII letters, digits, or hyphens",
                kind
            ),
        }
        .fail()
    }
}

/// Map a `std::io::Result` into [`Result`] with an [`Error::Io`]
/// carrying the path for context.
fn map_io<T>(res: std::io::Result<T>, path: &Path) -> Result<T> {
    res.map_err(|e| Error::Io {
        path: path.display().to_string(),
        message: Error::stringify(e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample(name: &str) -> TrustRoot {
        TrustRoot {
            name: name.to_string(),
            key_id: "0x0001".to_string(),
            fingerprint: "AAAA".to_string(),
            key_url: format!("/publishers/{}.asc", name),
        }
    }

    #[test]
    fn round_trips_trust_root() {
        let dir = tempdir().expect("tempdir");
        let store = TrustStore::open(dir.path()).expect("open");
        assert!(store.list().unwrap().is_empty());

        store.put(&sample("ribose")).expect("put");
        let got = store.get("ribose").expect("get").expect("present");
        assert_eq!(got, sample("ribose"));
        assert!(store.is_trusted("ribose").unwrap());

        let names = store.list().unwrap();
        assert_eq!(names, vec!["ribose"]);

        assert!(store.remove("ribose").unwrap());
        assert!(!store.is_trusted("ribose").unwrap());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn put_rejects_path_traversal() {
        let dir = tempdir().expect("tempdir");
        let store = TrustStore::open(dir.path()).expect("open");
        let bad = TrustRoot {
            name: "../escape".to_string(),
            ..sample("x")
        };
        let err = store.put(&bad).unwrap_err();
        assert!(matches!(err, Error::InvalidPublisherName { .. }));
    }

    #[test]
    fn get_rejects_absolute_path() {
        let dir = tempdir().expect("tempdir");
        let store = TrustStore::open(dir.path()).expect("open");
        let err = store.get("/etc/passwd").unwrap_err();
        assert!(matches!(err, Error::InvalidPublisherName { .. }));
    }

    #[test]
    fn rejects_dotdot_name() {
        let err = validate_publisher_name("..").unwrap_err();
        assert!(matches!(err, Error::InvalidPublisherName { .. }));
    }

    #[test]
    fn rejects_uppercase_name() {
        let err = validate_publisher_name("Ribose").unwrap_err();
        assert!(matches!(err, Error::InvalidPublisherName { .. }));
    }
}
