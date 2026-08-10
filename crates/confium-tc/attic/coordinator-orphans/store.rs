//! Persistent session store — pluggable backend for session state.
//!
//! Sessions are serialized to JSON and stored via a [`SessionStore`]
//! backend. On coordinator restart, sessions are loaded from the
//! store and restored to their last-persisted state.
//!
//! ## OCP design
//!
//! New backends (Redis, PostgreSQL, S3) are added by implementing
//! the [`SessionStore`] trait.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Serialized session snapshot — the unit of persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    /// Session ID.
    pub session_id: String,
    /// JSON-encoded session state.
    pub state_json: String,
    /// When the snapshot was taken.
    pub snapshot_at: chrono::DateTime<chrono::Utc>,
}

/// Errors during store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// I/O error.
    #[error("io error: {0}")]
    Io(String),
    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Trait for session persistence backends.
pub trait SessionStore: Send + Sync {
    /// Save a session snapshot.
    fn save(&self, snapshot: &SessionSnapshot) -> Result<(), StoreError>;

    /// Load a session snapshot by ID.
    fn load(&self, session_id: &str) -> Result<Option<SessionSnapshot>, StoreError>;

    /// Delete a session.
    fn delete(&self, session_id: &str) -> Result<(), StoreError>;

    /// List all stored session IDs.
    fn list(&self) -> Result<Vec<String>, StoreError>;
}

/// In-memory session store (default, no persistence).
#[derive(Default)]
pub struct InMemorySessionStore {
    entries: Mutex<HashMap<String, SessionSnapshot>>,
}

impl SessionStore for InMemorySessionStore {
    fn save(&self, snapshot: &SessionSnapshot) -> Result<(), StoreError> {
        self.entries
            .lock()
            .unwrap()
            .insert(snapshot.session_id.clone(), snapshot.clone());
        Ok(())
    }

    fn load(&self, session_id: &str) -> Result<Option<SessionSnapshot>, StoreError> {
        Ok(self.entries.lock().unwrap().get(session_id).cloned())
    }

    fn delete(&self, session_id: &str) -> Result<(), StoreError> {
        self.entries.lock().unwrap().remove(session_id);
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, StoreError> {
        Ok(self.entries.lock().unwrap().keys().cloned().collect())
    }
}

/// File-based session store. Each session is a JSON file in a
/// directory.
pub struct FileSessionStore {
    dir: PathBuf,
}

impl FileSessionStore {
    /// Create a new file store rooted at `dir`. Creates the directory
    /// if it doesn't exist.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(Self { dir })
    }

    fn session_path(&self, session_id: &str) -> PathBuf {
        let safe_name = session_id.replace('/', "_");
        self.dir.join(format!("{safe_name}.json"))
    }
}

impl SessionStore for FileSessionStore {
    fn save(&self, snapshot: &SessionSnapshot) -> Result<(), StoreError> {
        let path = self.session_path(&snapshot.session_id);
        let json = serde_json::to_string_pretty(snapshot)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        std::fs::write(&path, json).map_err(|e| StoreError::Io(e.to_string()))
    }

    fn load(&self, session_id: &str) -> Result<Option<SessionSnapshot>, StoreError> {
        let path = self.session_path(session_id);
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path).map_err(|e| StoreError::Io(e.to_string()))?;
        let snapshot: SessionSnapshot = serde_json::from_str(&contents)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        Ok(Some(snapshot))
    }

    fn delete(&self, session_id: &str) -> Result<(), StoreError> {
        let path = self.session_path(session_id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, StoreError> {
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(|e| StoreError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".json") {
                ids.push(id.to_string());
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_snapshot(id: &str) -> SessionSnapshot {
        SessionSnapshot {
            session_id: id.into(),
            state_json: r#"{"state":"pending"}"#.into(),
            snapshot_at: Utc::now(),
        }
    }

    // InMemorySessionStore tests

    #[test]
    fn in_memory_save_and_load() {
        let store = InMemorySessionStore::default();
        let snapshot = make_snapshot("s1");
        store.save(&snapshot).unwrap();
        let loaded = store.load("s1").unwrap().unwrap();
        assert_eq!(loaded.session_id, "s1");
    }

    #[test]
    fn in_memory_load_missing_returns_none() {
        let store = InMemorySessionStore::default();
        assert!(store.load("missing").unwrap().is_none());
    }

    #[test]
    fn in_memory_delete_removes_entry() {
        let store = InMemorySessionStore::default();
        store.save(&make_snapshot("s1")).unwrap();
        store.delete("s1").unwrap();
        assert!(store.load("s1").unwrap().is_none());
    }

    #[test]
    fn in_memory_list_returns_all() {
        let store = InMemorySessionStore::default();
        store.save(&make_snapshot("s1")).unwrap();
        store.save(&make_snapshot("s2")).unwrap();
        let mut ids = store.list().unwrap();
        ids.sort();
        assert_eq!(ids, vec!["s1", "s2"]);
    }

    #[test]
    fn in_memory_overwrite_on_save() {
        let store = InMemorySessionStore::default();
        store.save(&make_snapshot("s1")).unwrap();
        let mut updated = make_snapshot("s1");
        updated.state_json = r#"{"state":"completed"}"#.into();
        store.save(&updated).unwrap();
        let loaded = store.load("s1").unwrap().unwrap();
        assert!(loaded.state_json.contains("completed"));
    }

    // FileSessionStore tests

    #[test]
    fn file_store_creates_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/sessions");
        let _store = FileSessionStore::new(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn file_store_save_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSessionStore::new(tmp.path()).unwrap();
        store.save(&make_snapshot("s1")).unwrap();
        let loaded = store.load("s1").unwrap().unwrap();
        assert_eq!(loaded.session_id, "s1");
    }

    #[test]
    fn file_store_load_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSessionStore::new(tmp.path()).unwrap();
        assert!(store.load("missing").unwrap().is_none());
    }

    #[test]
    fn file_store_delete_removes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSessionStore::new(tmp.path()).unwrap();
        store.save(&make_snapshot("s1")).unwrap();
        assert!(store.load("s1").unwrap().is_some());
        store.delete("s1").unwrap();
        assert!(store.load("s1").unwrap().is_none());
    }

    #[test]
    fn file_store_list_returns_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSessionStore::new(tmp.path()).unwrap();
        store.save(&make_snapshot("s1")).unwrap();
        store.save(&make_snapshot("s2")).unwrap();
        let mut ids = store.list().unwrap();
        ids.sort();
        assert_eq!(ids, vec!["s1", "s2"]);
    }

    #[test]
    fn file_store_survives_across_instances() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let store = FileSessionStore::new(tmp.path()).unwrap();
            store.save(&make_snapshot("persistent")).unwrap();
        }
        {
            let store = FileSessionStore::new(tmp.path()).unwrap();
            let loaded = store.load("persistent").unwrap().unwrap();
            assert_eq!(loaded.session_id, "persistent");
        }
    }

    #[test]
    fn file_store_sanitizes_slashes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSessionStore::new(tmp.path()).unwrap();
        store.save(&make_snapshot("session/with/slashes")).unwrap();
        let loaded = store.load("session/with/slashes").unwrap().unwrap();
        assert_eq!(loaded.session_id, "session/with/slashes");
    }
}
