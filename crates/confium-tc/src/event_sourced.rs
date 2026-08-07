//! Event-sourced session store.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// A session event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    Created { session_id: String, threshold: u32, party_count: u32 },
    CommitmentSubmitted { session_id: String, signer_id: String },
    ShareSubmitted { session_id: String, signer_id: String },
    Completed { session_id: String },
    Expired { session_id: String },
    Aborted { session_id: String, reason: String },
}

/// An event log entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub event: SessionEvent,
}

/// Event-sourced session state projected from events.
#[derive(Debug, Clone, Default)]
pub struct SessionProjection {
    pub session_id: String,
    pub state: String,
    pub threshold: u32,
    pub party_count: u32,
    pub commitments: Vec<String>,
    pub shares: Vec<String>,
}

/// In-memory event store.
#[derive(Default)]
pub struct EventStore {
    events: Mutex<Vec<EventEntry>>,
    next_seq: Mutex<u64>,
}

impl EventStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&self, event: SessionEvent) -> u64 {
        let seq = {
            let mut next = self.next_seq.lock().unwrap();
            let s = *next;
            *next += 1;
            s
        };
        self.events.lock().unwrap().push(EventEntry {
            sequence: seq,
            timestamp: Utc::now(),
            event,
        });
        seq
    }

    pub fn all_events(&self) -> Vec<EventEntry> {
        self.events.lock().unwrap().clone()
    }

    pub fn events_for_session(&self, session_id: &str) -> Vec<EventEntry> {
        self.events.lock().unwrap().iter()
            .filter(|e| session_matches(&e.event, session_id))
            .cloned()
            .collect()
    }

    pub fn project_session(&self, session_id: &str) -> Option<SessionProjection> {
        let events = self.events_for_session(session_id);
        if events.is_empty() {
            return None;
        }
        let mut proj = SessionProjection::default();
        proj.session_id = session_id.into();
        for entry in &events {
            apply_event(&mut proj, &entry.event);
        }
        Some(proj)
    }

    pub fn project_all(&self) -> Vec<SessionProjection> {
        let session_ids: std::collections::HashSet<String> = self.events.lock().unwrap().iter()
            .filter_map(|e| session_id_of(&e.event))
            .collect();
        session_ids.iter()
            .filter_map(|sid| self.project_session(sid))
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn replay(&self) {
        // Events are already in the log; projection reads them
        let _ = self.all_events();
    }
}

fn session_matches(event: &SessionEvent, session_id: &str) -> bool {
    session_id_of(event).as_deref() == Some(session_id)
}

fn session_id_of(event: &SessionEvent) -> Option<String> {
    match event {
        SessionEvent::Created { session_id, .. } => Some(session_id.clone()),
        SessionEvent::CommitmentSubmitted { session_id, .. } => Some(session_id.clone()),
        SessionEvent::ShareSubmitted { session_id, .. } => Some(session_id.clone()),
        SessionEvent::Completed { session_id } => Some(session_id.clone()),
        SessionEvent::Expired { session_id } => Some(session_id.clone()),
        SessionEvent::Aborted { session_id, .. } => Some(session_id.clone()),
    }
}

fn apply_event(proj: &mut SessionProjection, event: &SessionEvent) {
    match event {
        SessionEvent::Created { threshold, party_count, .. } => {
            proj.state = "pending".into();
            proj.threshold = *threshold;
            proj.party_count = *party_count;
        }
        SessionEvent::CommitmentSubmitted { signer_id, .. } => {
            proj.commitments.push(signer_id.clone());
        }
        SessionEvent::ShareSubmitted { signer_id, .. } => {
            proj.shares.push(signer_id.clone());
        }
        SessionEvent::Completed { .. } => {
            proj.state = "completed".into();
        }
        SessionEvent::Expired { .. } => {
            proj.state = "expired".into();
        }
        SessionEvent::Aborted { .. } => {
            proj.state = "aborted".into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read() {
        let store = EventStore::new();
        store.append(SessionEvent::Created {
            session_id: "s1".into(), threshold: 2, party_count: 3,
        });
        assert_eq!(store.event_count(), 1);
    }

    #[test]
    fn project_session() {
        let store = EventStore::new();
        store.append(SessionEvent::Created {
            session_id: "s1".into(), threshold: 2, party_count: 3,
        });
        store.append(SessionEvent::CommitmentSubmitted {
            session_id: "s1".into(), signer_id: "alice".into(),
        });
        store.append(SessionEvent::Completed { session_id: "s1".into() });

        let proj = store.project_session("s1").unwrap();
        assert_eq!(proj.state, "completed");
        assert_eq!(proj.threshold, 2);
        assert_eq!(proj.commitments, vec!["alice"]);
    }

    #[test]
    fn project_all_sessions() {
        let store = EventStore::new();
        store.append(SessionEvent::Created {
            session_id: "s1".into(), threshold: 1, party_count: 1,
        });
        store.append(SessionEvent::Created {
            session_id: "s2".into(), threshold: 2, party_count: 3,
        });
        let all = store.project_all();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn events_for_specific_session() {
        let store = EventStore::new();
        store.append(SessionEvent::Created {
            session_id: "s1".into(), threshold: 2, party_count: 3,
        });
        store.append(SessionEvent::Created {
            session_id: "s2".into(), threshold: 2, party_count: 3,
        });
        assert_eq!(store.events_for_session("s1").len(), 1);
    }

    #[test]
    fn sequence_numbers_monotonic() {
        let store = EventStore::new();
        let s1 = store.append(SessionEvent::Created {
            session_id: "s1".into(), threshold: 2, party_count: 3,
        });
        let s2 = store.append(SessionEvent::Completed { session_id: "s1".into() });
        assert!(s1 < s2);
    }

    #[test]
    fn project_nonexistent_returns_none() {
        let store = EventStore::new();
        assert!(store.project_session("nope").is_none());
    }

    #[test]
    fn aborted_state() {
        let store = EventStore::new();
        store.append(SessionEvent::Created {
            session_id: "s1".into(), threshold: 2, party_count: 3,
        });
        store.append(SessionEvent::Aborted {
            session_id: "s1".into(), reason: "test".into(),
        });
        let proj = store.project_session("s1").unwrap();
        assert_eq!(proj.state, "aborted");
    }

    #[test]
    fn multiple_commitments_tracked() {
        let store = EventStore::new();
        store.append(SessionEvent::Created {
            session_id: "s1".into(), threshold: 2, party_count: 3,
        });
        store.append(SessionEvent::CommitmentSubmitted {
            session_id: "s1".into(), signer_id: "a".into(),
        });
        store.append(SessionEvent::CommitmentSubmitted {
            session_id: "s1".into(), signer_id: "b".into(),
        });
        let proj = store.project_session("s1").unwrap();
        assert_eq!(proj.commitments.len(), 2);
    }
}
