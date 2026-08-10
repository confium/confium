//! Signing session timeout — per-session deadline enforcement.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// A session deadline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDeadline {
    pub session_id: String,
    pub deadline: DateTime<Utc>,
}

/// Manages per-session deadlines.
#[derive(Default)]
pub struct SessionTimeoutManager {
    deadlines: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl SessionTimeoutManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a deadline for a session.
    pub fn set_deadline(&self, session_id: &str, timeout: Duration) {
        let deadline = Utc::now() + timeout;
        self.deadlines.lock().unwrap().insert(session_id.into(), deadline);
    }

    /// Remove a session's deadline (session completed).
    pub fn clear(&self, session_id: &str) {
        self.deadlines.lock().unwrap().remove(session_id);
    }

    /// Get all sessions that have exceeded their deadline.
    pub fn expired_sessions(&self) -> Vec<SessionDeadline> {
        let now = Utc::now();
        self.deadlines
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, deadline)| **deadline < now)
            .map(|(sid, deadline)| SessionDeadline {
                session_id: sid.clone(),
                deadline: *deadline,
            })
            .collect()
    }

    /// Number of tracked sessions.
    pub fn count(&self) -> usize {
        self.deadlines.lock().unwrap().len()
    }

    /// Check if a specific session is expired.
    pub fn is_expired(&self, session_id: &str) -> bool {
        let now = Utc::now();
        self.deadlines
            .lock()
            .unwrap()
            .get(session_id)
            .map(|d| *d < now)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_check_not_expired() {
        let mgr = SessionTimeoutManager::new();
        mgr.set_deadline("s1", Duration::minutes(5));
        assert!(!mgr.is_expired("s1"));
    }

    #[test]
    fn expired_after_deadline() {
        let mgr = SessionTimeoutManager::new();
        mgr.set_deadline("s1", Duration::seconds(-1)); // already past
        assert!(mgr.is_expired("s1"));
    }

    #[test]
    fn clear_removes_deadline() {
        let mgr = SessionTimeoutManager::new();
        mgr.set_deadline("s1", Duration::minutes(5));
        mgr.clear("s1");
        assert!(!mgr.is_expired("s1"));
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn expired_sessions_returns_list() {
        let mgr = SessionTimeoutManager::new();
        mgr.set_deadline("s1", Duration::minutes(5));
        mgr.set_deadline("s2", Duration::seconds(-1));
        mgr.set_deadline("s3", Duration::seconds(-1));
        let expired = mgr.expired_sessions();
        assert_eq!(expired.len(), 2);
    }

    #[test]
    fn count_tracks_sessions() {
        let mgr = SessionTimeoutManager::new();
        assert_eq!(mgr.count(), 0);
        mgr.set_deadline("s1", Duration::minutes(5));
        mgr.set_deadline("s2", Duration::minutes(5));
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn unknown_session_not_expired() {
        let mgr = SessionTimeoutManager::new();
        assert!(!mgr.is_expired("unknown"));
    }
}
