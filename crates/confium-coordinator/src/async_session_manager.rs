//! Async session manager — non-blocking session lifecycle.
//!
//! Provides an async interface for session creation, commitment
//! collection, and aggregation. Uses std::thread channels under the
//! hood (not tokio) for compatibility.

use crate::coordinator::coordinator::Coordinator;
use crate::coordinator::session::{SessionId, SessionRequest, SessionState};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

/// Async session manager.
pub struct AsyncSessionManager {
    sender: Sender<AsyncOp>,
}

enum AsyncOp {
    CreateSession(SessionRequest),
    SubmitCommitment(String, String, Vec<u8>),
    SubmitShare(String, String, Vec<u8>),
    Shutdown,
}

impl AsyncSessionManager {
    /// Create a new async session manager wrapping the coordinator.
    pub fn spawn(coord: std::sync::Arc<std::sync::Mutex<Coordinator>>) -> Self {
        let (tx, rx) = channel();
        thread::spawn(move || {
            Self::run_loop(coord, rx);
        });
        Self { sender: tx }
    }

    fn run_loop(coord: std::sync::Arc<std::sync::Mutex<Coordinator>>, rx: Receiver<AsyncOp>) {
        while let Ok(op) = rx.recv() {
            match op {
                AsyncOp::CreateSession(req) => {
                    let _ = coord.lock().unwrap().create_session(req);
                }
                AsyncOp::SubmitCommitment(sid, signer, bytes) => {
                    use crate::coordinator::session::Commitment;
                    let _ = coord.lock().unwrap().submit_commitment(
                        &sid,
                        Commitment {
                            signer_id: signer,
                            bytes,
                            signer_signature: vec![0u8; 64],
                            submitted_at: chrono::Utc::now(),
                        },
                    );
                }
                AsyncOp::SubmitShare(sid, signer, bytes) => {
                    use crate::coordinator::session::Share;
                    let _ = coord.lock().unwrap().submit_share(
                        &sid,
                        Share {
                            signer_id: signer,
                            bytes,
                            signer_signature: vec![0u8; 64],
                            submitted_at: chrono::Utc::now(),
                        },
                    );
                }
                AsyncOp::Shutdown => break,
            }
        }
    }

    /// Asynchronously create a session.
    pub fn create_session(&self, request: SessionRequest) {
        let _ = self.sender.send(AsyncOp::CreateSession(request));
    }

    /// Asynchronously submit a commitment.
    pub fn submit_commitment(&self, session_id: &str, signer_id: &str, bytes: Vec<u8>) {
        let _ = self.sender.send(AsyncOp::SubmitCommitment(
            session_id.into(),
            signer_id.into(),
            bytes,
        ));
    }

    /// Asynchronously submit a share.
    pub fn submit_share(&self, session_id: &str, signer_id: &str, bytes: Vec<u8>) {
        let _ = self.sender.send(AsyncOp::SubmitShare(
            session_id.into(),
            signer_id.into(),
            bytes,
        ));
    }

    /// Shutdown the background thread.
    pub fn shutdown(&self) {
        let _ = self.sender.send(AsyncOp::Shutdown);
    }
}

/// Async session info: non-blocking query.
pub struct AsyncSessionInfo {
    pub session_id: SessionId,
    pub state: SessionState,
}

/// Track pending async operations.
#[derive(Default)]
pub struct PendingOpsTracker {
    pending: HashMap<SessionId, Vec<String>>,
}

impl PendingOpsTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_op(&mut self, session_id: &str, op: &str) {
        self.pending
            .entry(session_id.into())
            .or_default()
            .push(op.into());
    }

    pub fn pending_ops(&self, session_id: &str) -> Vec<String> {
        self.pending.get(session_id).cloned().unwrap_or_default()
    }

    pub fn clear_session(&mut self, session_id: &str) {
        self.pending.remove(session_id);
    }

    pub fn total_pending(&self) -> usize {
        self.pending.values().map(|v| v.len()).sum()
    }
}

/// Wait for a session to reach a target state, polling.
pub fn wait_for_state(
    coord: &Coordinator,
    session_id: &str,
    target: SessionState,
    timeout: Duration,
) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(state) = coord.session_state(session_id) {
            if state == target {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn async_create_session() {
        let coord = Arc::new(Mutex::new(Coordinator::new()));
        let manager = AsyncSessionManager::spawn(Arc::clone(&coord));

        let request = SessionRequest {
            quorum_id: "q1".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: 60,
            requested_by: "async-test".into(),
        };
        manager.create_session(request);

        // Wait briefly for processing
        thread::sleep(Duration::from_millis(50));
        assert_eq!(coord.lock().unwrap().session_count(), 1);
        manager.shutdown();
    }

    #[test]
    fn pending_ops_tracker() {
        let mut tracker = PendingOpsTracker::new();
        tracker.record_op("s1", "create");
        tracker.record_op("s1", "commit");
        tracker.record_op("s2", "share");
        assert_eq!(tracker.pending_ops("s1").len(), 2);
        assert_eq!(tracker.pending_ops("s2").len(), 1);
        assert_eq!(tracker.total_pending(), 3);
        tracker.clear_session("s1");
        assert_eq!(tracker.total_pending(), 1);
    }

    #[test]
    fn wait_for_state_timeout() {
        let mut coord = Coordinator::new();
        let req = SessionRequest {
            quorum_id: "q".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: 60,
            requested_by: "test".into(),
        };
        let sid = coord.create_session(req).unwrap();
        // Session is Pending, not Completed - timeout
        let completed = wait_for_state(
            &coord,
            &sid,
            SessionState::Completed,
            Duration::from_millis(50),
        );
        assert!(!completed);
    }

    #[test]
    fn async_commitment_submission() {
        let coord = Arc::new(Mutex::new(Coordinator::new()));
        let manager = AsyncSessionManager::spawn(Arc::clone(&coord));

        let request = SessionRequest {
            quorum_id: "q1".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: 60,
            requested_by: "test".into(),
        };
        let sid = coord.lock().unwrap().create_session(request).unwrap();
        manager.submit_commitment(&sid, "alice", vec![0xAA; 32]);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            coord.lock().unwrap().session_commitment_count(&sid),
            Some(1)
        );
        manager.shutdown();
    }

    #[test]
    fn async_share_submission() {
        let coord = Arc::new(Mutex::new(Coordinator::new()));
        let manager = AsyncSessionManager::spawn(Arc::clone(&coord));

        let request = SessionRequest {
            quorum_id: "q1".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: 60,
            requested_by: "test".into(),
        };
        let sid = coord.lock().unwrap().create_session(request).unwrap();
        manager.submit_share(&sid, "alice", vec![0xBB; 32]);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(coord.lock().unwrap().session_share_count(&sid), Some(1));
        manager.shutdown();
    }
}
