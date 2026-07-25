//! Local trust store.
//!
//! The user's trusted publishers live under
//! `~/.config/confium/trust/<publisher>.toml`, one file per publisher.
//! Each file mirrors the `[[publisher]]` row from the registry's
//! `trust-roots.toml` so the same [`TrustRoot`] type round-trips through
//! both. This makes "trust a publisher" a simple file write — auditable,
//! mergeable, and trivially backed up.
//!
//! [`TrustStore`] owns the file-layout knowledge so the CLI's `trust`
//! sub-commands stay thin.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::manifest::TrustRoot;
use crate::paths::trust_dir;

/// One row in the local trust store.
pub type TrustStoreEntry = TrustRoot;

/// A handle on the local trust directory.
///
/// Construct with [`TrustStore::new`] (real home) or
/// [`TrustStore::for_home`] (tests). All operations are file-backed; the
/// type holds no in-memory cache so concurrent edits by external tools
/// are picked up on the next read.
pub struct TrustStore {
    override_home: Option<PathBuf>,
}

impl TrustStore {
    /// Bind to the user's real trust directory.
    pub fn new() -> Self {
        TrustStore {
            override_home: None,
        }
    }

    /// Bind to `<override_home>/.config/confium/trust`.
    pub fn for_home(override_home: PathBuf) -> Self {
        TrustStore {
            override_home: Some(override_home),
        }
    }

    /// The trust directory backing this store.
    pub fn dir(&self) -> Result<PathBuf> {
        trust_dir(self.override_home.as_ref())
    }

    /// List trusted publishers, sorted by name.
    pub fn list(&self) -> Result<Vec<TrustStoreEntry>> {
        let dir = self.dir()?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        let read = std::fs::read_dir(&dir)
            .map_err(|e| Error::io(e, format!("failed to read {}", dir.display())))?;
        for entry in read {
            let entry = entry.map_err(|e| Error::io(e, "directory iteration error"))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            if let Ok(root) = self.read_file(&path) {
                entries.push(root);
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Add (or replace) a trusted publisher.
    pub fn add(&self, root: TrustStoreEntry) -> Result<()> {
        let dir = self.dir()?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::io(e, format!("failed to create {}", dir.display())))?;
        let path = self.path_for(&root.name);
        // Single-publisher file: write just the [[publisher]] row to keep
        // the format minimal and human-editable.
        let body = toml::to_string(&root).map_err(|e| Error::TomlSerialize { source: e })?;
        std::fs::write(&path, body)
            .map_err(|e| Error::io(e, format!("failed to write {}", path.display())))?;
        Ok(())
    }

    /// Remove a trusted publisher. Succeeds (no-op) if not present.
    pub fn remove(&self, name: &str) -> Result<bool> {
        let path = self.path_for(name);
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path)
            .map_err(|e| Error::io(e, format!("failed to remove {}", path.display())))?;
        Ok(true)
    }

    /// True if `name` is trusted.
    pub fn contains(&self, name: &str) -> Result<bool> {
        Ok(self.path_for(name).exists())
    }

    fn path_for(&self, name: &str) -> PathBuf {
        // Sanitize the publisher name so it can't escape the trust dir.
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(format!("{safe}.toml"))
    }

    fn read_file(&self, path: &Path) -> Result<TrustStoreEntry> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| Error::io(e, format!("failed to read {}", path.display())))?;
        toml::from_str(&body).map_err(|e| Error::TomlParse {
            path: path.display().to_string(),
            source: e,
        })
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> TrustStoreEntry {
        TrustRoot {
            name: name.to_string(),
            key_id: "0xABCD".to_string(),
            fingerprint: "AAAA BBBB".to_string(),
            key_url: format!("/publishers/{name}.asc"),
        }
    }

    #[test]
    fn list_on_missing_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TrustStore::for_home(PathBuf::from(tmp.path()));
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn add_then_list() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TrustStore::for_home(PathBuf::from(tmp.path()));
        store.add(root("ribose")).unwrap();
        let entries = store.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ribose");
    }

    #[test]
    fn add_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TrustStore::for_home(PathBuf::from(tmp.path()));
        store.add(root("ribose")).unwrap();
        let mut updated = root("ribose");
        updated.fingerprint = "CCCC".to_string();
        store.add(updated).unwrap();
        let entries = store.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fingerprint, "CCCC");
    }

    #[test]
    fn remove_returns_true_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TrustStore::for_home(PathBuf::from(tmp.path()));
        store.add(root("ribose")).unwrap();
        assert!(store.remove("ribose").unwrap());
        assert!(!store.contains("ribose").unwrap());
    }

    #[test]
    fn remove_returns_false_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TrustStore::for_home(PathBuf::from(tmp.path()));
        assert!(!store.remove("ghost").unwrap());
    }

    #[test]
    fn path_for_sanitizes_dangerous_names() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TrustStore::for_home(PathBuf::from(tmp.path()));
        let path = store.path_for("../etc/passwd");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(!name.contains('/'));
        assert!(!name.contains(".."));
    }
}
