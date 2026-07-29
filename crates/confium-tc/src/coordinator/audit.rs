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
}
