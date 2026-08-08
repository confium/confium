//! Audit log for coordinator sessions.

use crate::coordinator::session::{SessionId, SignerId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Type of event.
    pub event: AuditEvent,
    /// Session involved.
    pub session_id: SessionId,
}

/// Type of audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Session created.
    SessionCreated {
        /// Requesting actor.
        requested_by: SignerId,
        /// Quorum.
        quorum_id: String,
    },
    /// Commitment received from signer.
    CommitmentReceived {
        /// Signer.
        signer: SignerId,
    },
    /// Share received from signer.
    ShareReceived {
        /// Signer.
        signer: SignerId,
    },
    /// Aggregation completed.
    Aggregated,
    /// Session expired.
    Expired,
    /// Session aborted.
    Aborted {
        /// Reason.
        reason: String,
    },
}

/// Append-only audit log.
#[derive(Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Construct a new empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry.
    pub fn append(&mut self, session_id: impl Into<SessionId>, event: AuditEvent) {
        self.entries.push(AuditEntry {
            timestamp: Utc::now(),
            event,
            session_id: session_id.into(),
        });
    }

    /// Get all entries for a session.
    pub fn entries_for(&self, session_id: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.session_id == session_id)
            .collect()
    }

    /// All entries.
    pub fn all(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Serialize to JSONL.
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&serde_json::to_string(entry)?);
            out.push('\n');
        }
        Ok(out)
    }

    /// Export as a JSON array.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entries)
    }

    /// Total entry count.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Run a structured query against the audit log. Only non-None
    /// filters are applied — an empty query returns all entries.
    pub fn query(&self, query: &AuditQuery) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| query.matches(e)).collect()
    }

    /// All events involving a specific signer.
    pub fn query_by_signer(&self, signer_id: &str) -> Vec<&AuditEntry> {
        self.query(&AuditQuery {
            signer_id: Some(signer_id.into()),
            ..Default::default()
        })
    }

    /// All events within a time range (inclusive).
    pub fn query_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<&AuditEntry> {
        self.query(&AuditQuery {
            time_start: Some(start),
            time_end: Some(end),
            ..Default::default()
        })
    }
}

/// Structured query filter for the audit log. All fields are optional;
/// `None` means "no filter on this dimension".
#[derive(Debug, Default, Clone)]
pub struct AuditQuery {
    /// Filter by session ID.
    pub session_id: Option<String>,
    /// Filter by signer ID (matches any event involving this signer).
    pub signer_id: Option<String>,
    /// Filter by event type name (e.g., "session_created", "aggregated").
    pub event_type: Option<String>,
    /// Filter: events at or after this time.
    pub time_start: Option<DateTime<Utc>>,
    /// Filter: events at or before this time.
    pub time_end: Option<DateTime<Utc>>,
}

impl AuditQuery {
    /// Check if an entry matches this query.
    fn matches(&self, entry: &AuditEntry) -> bool {
        if let Some(ref sid) = self.session_id {
            if &entry.session_id != sid {
                return false;
            }
        }
        if let Some(ref signer) = self.signer_id {
            if !entry.involves_signer(signer) {
                return false;
            }
        }
        if let Some(ref etype) = self.event_type {
            if entry.event_type_name() != etype {
                return false;
            }
        }
        if let Some(start) = self.time_start {
            if entry.timestamp < start {
                return false;
            }
        }
        if let Some(end) = self.time_end {
            if entry.timestamp > end {
                return false;
            }
        }
        true
    }

    /// Create a new empty query (matches all entries).
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditEntry {
    /// Does this entry involve the given signer?
    pub fn involves_signer(&self, signer_id: &str) -> bool {
        match &self.event {
            AuditEvent::SessionCreated { requested_by, .. } => requested_by == signer_id,
            AuditEvent::CommitmentReceived { signer } => signer == signer_id,
            AuditEvent::ShareReceived { signer } => signer == signer_id,
            _ => false,
        }
    }

    /// Event type as a snake_case string.
    pub fn event_type_name(&self) -> &'static str {
        match &self.event {
            AuditEvent::SessionCreated { .. } => "session_created",
            AuditEvent::CommitmentReceived { .. } => "commitment_received",
            AuditEvent::ShareReceived { .. } => "share_received",
            AuditEvent::Aggregated => "aggregated",
            AuditEvent::Expired => "expired",
            AuditEvent::Aborted { .. } => "aborted",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_query() {
        let mut log = AuditLog::new();
        log.append(
            "session-1",
            AuditEvent::SessionCreated {
                requested_by: "alice".into(),
                quorum_id: "biml-root".into(),
            },
        );
        log.append(
            "session-1",
            AuditEvent::CommitmentReceived {
                signer: "alice".into(),
            },
        );
        log.append(
            "session-2",
            AuditEvent::SessionCreated {
                requested_by: "bob".into(),
                quorum_id: "biml-root".into(),
            },
        );

        let s1_entries = log.entries_for("session-1");
        assert_eq!(s1_entries.len(), 2);
        let s2_entries = log.entries_for("session-2");
        assert_eq!(s2_entries.len(), 1);
    }

    #[test]
    fn jsonl_round_trips() {
        let mut log = AuditLog::new();
        log.append("session-1", AuditEvent::Aggregated);
        let jsonl = log.to_jsonl().unwrap();
        assert!(jsonl.contains("session-1"));
        assert!(jsonl.contains("aggregated"));
    }

    #[test]
    fn query_by_signer() {
        let mut log = AuditLog::new();
        log.append(
            "s1",
            AuditEvent::SessionCreated {
                requested_by: "alice".into(),
                quorum_id: "q".into(),
            },
        );
        log.append(
            "s1",
            AuditEvent::CommitmentReceived {
                signer: "alice".into(),
            },
        );
        log.append(
            "s1",
            AuditEvent::ShareReceived {
                signer: "bob".into(),
            },
        );

        let alice_events = log.query_by_signer("alice");
        assert_eq!(alice_events.len(), 2);
        let bob_events = log.query_by_signer("bob");
        assert_eq!(bob_events.len(), 1);
        let nobody = log.query_by_signer("nobody");
        assert_eq!(nobody.len(), 0);
    }

    #[test]
    fn query_by_time_range() {
        let mut log = AuditLog::new();
        log.append("s1", AuditEvent::Aggregated);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mid = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        log.append("s2", AuditEvent::Aggregated);

        let before = log.query_by_time_range(Utc::now() - chrono::Duration::minutes(1), mid);
        assert_eq!(before.len(), 1);
        let after = log.query_by_time_range(mid, Utc::now() + chrono::Duration::minutes(1));
        assert_eq!(after.len(), 1);
    }

    #[test]
    fn query_empty_returns_all() {
        let mut log = AuditLog::new();
        log.append("s1", AuditEvent::Aggregated);
        log.append("s2", AuditEvent::Expired);
        let all = log.query(&AuditQuery::new());
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn query_by_event_type() {
        let mut log = AuditLog::new();
        log.append("s1", AuditEvent::Aggregated);
        log.append("s2", AuditEvent::Expired);
        log.append("s3", AuditEvent::Aggregated);

        let agg = log.query(&AuditQuery {
            event_type: Some("aggregated".into()),
            ..Default::default()
        });
        assert_eq!(agg.len(), 2);
    }

    #[test]
    fn count_works() {
        let mut log = AuditLog::new();
        assert_eq!(log.count(), 0);
        log.append("s1", AuditEvent::Aggregated);
        log.append("s2", AuditEvent::Expired);
        assert_eq!(log.count(), 2);
    }

    #[test]
    fn export_json_returns_array() {
        let mut log = AuditLog::new();
        log.append("s1", AuditEvent::Aggregated);
        let json = log.export_json().unwrap();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("aggregated"));
    }

    #[test]
    fn involves_signer_checks_all_event_types() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event: AuditEvent::SessionCreated {
                requested_by: "alice".into(),
                quorum_id: "q".into(),
            },
            session_id: "s1".into(),
        };
        assert!(entry.involves_signer("alice"));
        assert!(!entry.involves_signer("bob"));
    }
}
