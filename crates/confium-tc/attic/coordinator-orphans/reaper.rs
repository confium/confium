//! Session reaper — background thread that expires stale sessions.
//!
//! Sessions have an unlock window (default 4 hours). After it elapses,
//! the session transitions to Expired, fires an audit event, and
//! decrements the active session counter. Without reaping, stale
//! sessions accumulate indefinitely.

use crate::coordinator::audit::AuditEvent;
use crate::coordinator::coordinator::Coordinator;
use crate::coordinator::session::SessionState;
use chrono::Utc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Configuration for the session reaper.
#[derive(Debug, Clone)]
pub struct ReaperConfig {
    /// How often to scan for expired sessions.
    pub scan_interval: Duration,
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self {
            scan_interval: Duration::from_secs(60),
        }
    }
}

/// Background session reaper. Runs in its own thread, periodically
/// scanning the coordinator for expired sessions.
pub struct SessionReaper {
    coordinator: Arc<Mutex<Coordinator>>,
    config: ReaperConfig,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl SessionReaper {
    /// Create a new reaper for the given shared coordinator.
    pub fn new(coordinator: Arc<Mutex<Coordinator>>, config: ReaperConfig) -> Self {
        Self {
            coordinator,
            config,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the reaper in a background thread.
    pub fn start(&self) {
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);
        let coordinator = Arc::clone(&self.coordinator);
        let interval = self.config.scan_interval;
        let running = Arc::clone(&self.running);

        thread::spawn(move || {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                reap_expired_sessions(&coordinator);
                thread::sleep(interval);
            }
        });
    }

    /// Stop the reaper.
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Run one reaping pass synchronously. Returns the number of
    /// sessions that were expired.
    pub fn reap_once(&self) -> usize {
        reap_expired_sessions(&self.coordinator)
    }
}

fn reap_expired_sessions(coordinator: &Arc<Mutex<Coordinator>>) -> usize {
    let mut coord = coordinator.lock().unwrap();
    let now = Utc::now();

    let pending: Vec<String> = coord
        .session_ids()
        .into_iter()
        .filter(|sid| coord.session_state(sid) == Some(SessionState::Pending))
        .collect();

    let mut expired_count = 0;
    for sid in pending {
        let should_expire = coord
            .session_mut(&sid)
            .map(|s| !s.is_unlocked(now))
            .unwrap_or(false);
        if should_expire {
            coord.set_session_state(&sid, SessionState::Expired);
            coord.audit_log_mut().append(sid.clone(), AuditEvent::Expired);
            expired_count += 1;
            tracing::info!(session = %sid, "session expired by reaper");
        }
    }
    expired_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::coordinator::Coordinator;
    use crate::coordinator::session::SessionRequest;

    fn make_request(unlock_minutes: i64) -> SessionRequest {
        SessionRequest {
            quorum_id: "q".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: unlock_minutes as u32,
            requested_by: "test".into(),
        }
    }

    #[test]
    fn reap_expires_past_unlock_window() {
        let coord = Arc::new(Mutex::new(Coordinator::new()));
        coord.lock().unwrap().create_session(make_request(0)).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        let reaper = SessionReaper::new(Arc::clone(&coord), ReaperConfig::default());
        let count = reaper.reap_once();
        assert_eq!(count, 1);
    }

    #[test]
    fn reap_preserves_active_sessions() {
        let coord = Arc::new(Mutex::new(Coordinator::new()));
        coord.lock().unwrap().create_session(make_request(240)).unwrap();
        let reaper = SessionReaper::new(Arc::clone(&coord), ReaperConfig::default());
        let count = reaper.reap_once();
        assert_eq!(count, 0);
    }

    #[test]
    fn reap_does_not_touch_completed_sessions() {
        let coord = Arc::new(Mutex::new(Coordinator::new()));
        let sid = coord.lock().unwrap().create_session(make_request(0)).unwrap();
        coord.lock().unwrap().set_session_state(&sid, SessionState::Completed);
        std::thread::sleep(Duration::from_millis(1100));
        let reaper = SessionReaper::new(Arc::clone(&coord), ReaperConfig::default());
        let count = reaper.reap_once();
        assert_eq!(count, 0);
    }

    #[test]
    fn reap_multiple_expired() {
        let coord = Arc::new(Mutex::new(Coordinator::new()));
        coord.lock().unwrap().create_session(make_request(0)).unwrap();
        coord.lock().unwrap().create_session(make_request(0)).unwrap();
        coord.lock().unwrap().create_session(make_request(240)).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        let reaper = SessionReaper::new(Arc::clone(&coord), ReaperConfig::default());
        let count = reaper.reap_once();
        assert_eq!(count, 2);
    }

    #[test]
    fn reap_empty_coordinator_returns_zero() {
        let coord = Arc::new(Mutex::new(Coordinator::new()));
        let reaper = SessionReaper::new(coord, ReaperConfig::default());
        assert_eq!(reaper.reap_once(), 0);
    }

    #[test]
    fn config_default_scan_interval_is_60s() {
        let config = ReaperConfig::default();
        assert_eq!(config.scan_interval, Duration::from_secs(60));
    }
}
