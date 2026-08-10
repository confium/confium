//! Idempotency keys — retry-safe session creation.
//!
//! When a client provides an idempotency key, the coordinator stores
//! the key → session_id mapping. A retried request with the same key
//! returns the original session instead of creating a duplicate.
//!
//! ## OCP design
//!
//! The [`IdempotencyStore`] trait allows different backends (in-memory,
//! Redis, database). New backends are added by implementing the trait.

use crate::coordinator::coordinator::Coordinator;
use crate::coordinator::session::{SessionError, SessionId, SessionRequest};
use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for idempotency key stores.
pub trait IdempotencyStore: Send + Sync {
    /// Look up a session by idempotency key. Returns `Some(session_id)`
    /// if the key was previously used.
    fn lookup(&self, key: &str) -> Option<SessionId>;

    /// Record a key → session mapping.
    fn record(&self, key: &str, session_id: &SessionId);
}

/// In-memory idempotency store. Thread-safe via Mutex.
#[derive(Default)]
pub struct InMemoryIdempotencyStore {
    entries: Mutex<HashMap<String, SessionId>>,
}

impl IdempotencyStore for InMemoryIdempotencyStore {
    fn lookup(&self, key: &str) -> Option<SessionId> {
        self.entries.lock().unwrap().get(key).cloned()
    }

    fn record(&self, key: &str, session_id: &SessionId) {
        self.entries
            .lock()
            .unwrap()
            .insert(key.to_string(), session_id.clone());
    }
}

/// Extension trait for [`Coordinator`] adding idempotent session creation.
pub trait IdempotentCoordinator {
    /// Create a session with an idempotency key. If the key was
    /// previously used, returns the original session_id.
    fn create_session_with_idempotacy(
        &mut self,
        request: SessionRequest,
        key: &str,
        store: &dyn IdempotencyStore,
    ) -> Result<SessionId, SessionError>;
}

impl IdempotentCoordinator for Coordinator {
    fn create_session_with_idempotacy(
        &mut self,
        request: SessionRequest,
        key: &str,
        store: &dyn IdempotencyStore,
    ) -> Result<SessionId, SessionError> {
        if let Some(existing) = store.lookup(key) {
            tracing::debug!(idempotency_key = %key, session = %existing, "idempotent hit");
            return Ok(existing);
        }
        let session_id = self.create_session(request)?;
        store.record(key, &session_id);
        tracing::debug!(idempotency_key = %key, session = %session_id, "idempotent miss → stored");
        Ok(session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request() -> SessionRequest {
        SessionRequest {
            quorum_id: "q".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: 60,
            requested_by: "test".into(),
        }
    }

    #[test]
    fn first_call_creates_session() {
        let store = InMemoryIdempotencyStore::default();
        let mut coord = Coordinator::new();
        let sid = coord
            .create_session_with_idempotacy(make_request(), "key-1", &store)
            .unwrap();
        assert!(sid.starts_with("session-"));
    }

    #[test]
    fn retry_returns_same_session() {
        let store = InMemoryIdempotencyStore::default();
        let mut coord = Coordinator::new();
        let sid1 = coord
            .create_session_with_idempotacy(make_request(), "key-1", &store)
            .unwrap();
        let sid2 = coord
            .create_session_with_idempotacy(make_request(), "key-1", &store)
            .unwrap();
        assert_eq!(sid1, sid2);
        assert_eq!(coord.session_count(), 1);
    }

    #[test]
    fn different_keys_create_different_sessions() {
        let store = InMemoryIdempotencyStore::default();
        let mut coord = Coordinator::new();
        let sid1 = coord
            .create_session_with_idempotacy(make_request(), "key-A", &store)
            .unwrap();
        let sid2 = coord
            .create_session_with_idempotacy(make_request(), "key-B", &store)
            .unwrap();
        assert_ne!(sid1, sid2);
        assert_eq!(coord.session_count(), 2);
    }

    #[test]
    fn store_lookup_returns_recorded() {
        let store = InMemoryIdempotencyStore::default();
        store.record("k1", &"session-42".to_string());
        assert_eq!(store.lookup("k1"), Some("session-42".into()));
    }

    #[test]
    fn store_lookup_unknown_returns_none() {
        let store = InMemoryIdempotencyStore::default();
        assert!(store.lookup("unknown").is_none());
    }

    #[test]
    fn store_overwrite_updates_value() {
        let store = InMemoryIdempotencyStore::default();
        store.record("k1", &"session-A".to_string());
        store.record("k1", &"session-B".to_string());
        assert_eq!(store.lookup("k1"), Some("session-B".into()));
    }

    #[test]
    fn many_keys_dont_interfere() {
        let store = InMemoryIdempotencyStore::default();
        let mut coord = Coordinator::new();
        for i in 0..10 {
            let key = format!("key-{i}");
            coord
                .create_session_with_idempotacy(make_request(), &key, &store)
                .unwrap();
        }
        assert_eq!(coord.session_count(), 10);
        for i in 0..10 {
            let key = format!("key-{i}");
            coord
                .create_session_with_idempotacy(make_request(), &key, &store)
                .unwrap();
        }
        assert_eq!(coord.session_count(), 10);
    }

    #[test]
    fn idempotent_with_repeated_failures() {
        let store = InMemoryIdempotencyStore::default();
        let mut coord = Coordinator::new();
        let mut last_sid = String::new();
        for _ in 0..5 {
            last_sid = coord
                .create_session_with_idempotacy(make_request(), "retry-key", &store)
                .unwrap();
        }
        assert_eq!(coord.session_count(), 1);
        assert!(store.lookup("retry-key").is_some());
        let _ = last_sid;
    }
}
