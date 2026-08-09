//! Certificate Transparency (CT) log integration.
//!
//! Submit threshold-signed events to public CT logs for independent
//! auditability. CT logs (RFC 6962) provide append-only proof of
//! certificate issuance.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A CT log entry to be submitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtEntry {
    /// Certificate or event hash (SHA-256).
    pub cert_hash_hex: String,
    /// Issuer name.
    pub issuer: String,
    /// Submission timestamp.
    pub submitted_at: DateTime<Utc>,
    /// Optional signature (e.g., from threshold key).
    pub signature_hex: Option<String>,
}

/// CT log submission status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtSubmissionStatus {
    Pending,
    Accepted,
    Rejected { reason: String },
    AlreadyIncluded,
}

/// Result of a CT submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtSubmissionResult {
    pub entry: CtEntry,
    pub status: CtSubmissionStatus,
    pub log_id: String,
    pub sct_hex: Option<String>, // Signed Certificate Timestamp
}

/// Configuration for a CT log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtLogConfig {
    pub log_id: String,
    pub url: String,
    pub public_key_hex: String,
    pub max_entry_size: usize,
}

/// A CT log client (simplified, mock-friendly).
pub struct CtClient {
    pub log: CtLogConfig,
    pending: std::sync::Mutex<Vec<CtEntry>>,
}

impl CtClient {
    pub fn new(log: CtLogConfig) -> Self {
        Self {
            log,
            pending: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Queue an entry for submission.
    pub fn queue_entry(&self, entry: CtEntry) {
        self.pending.lock().unwrap().push(entry);
    }

    /// Process all pending entries. Returns results.
    pub fn process_pending(&self) -> Vec<CtSubmissionResult> {
        let mut pending = self.pending.lock().unwrap();
        let results: Vec<CtSubmissionResult> = pending
            .drain(..)
            .map(|entry| {
                // Simplified: auto-accept if within size limit
                let status = if entry.cert_hash_hex.len() / 2 <= self.log.max_entry_size {
                    CtSubmissionStatus::Accepted
                } else {
                    CtSubmissionStatus::Rejected { reason: "too large".into() }
                };
                let sct = if matches!(status, CtSubmissionStatus::Accepted) {
                    Some(format!("sct-{}", entry.cert_hash_hex))
                } else {
                    None
                };
                CtSubmissionResult {
                    entry,
                    status,
                    log_id: self.log.log_id.clone(),
                    sct_hex: sct,
                }
            })
            .collect();
        results
    }

    /// Compute an inclusion proof for an entry (mock).
    pub fn inclusion_proof(&self, entry_hash: &str) -> Vec<String> {
        // Real implementation would query the CT log via its API.
        // Simplified mock proof.
        vec![format!("proof-{}", entry_hash)]
    }

    /// Get the number of pending entries.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(hash: impl Into<String>) -> CtEntry {
        CtEntry {
            cert_hash_hex: hash.into(),
            issuer: "confium-test".into(),
            submitted_at: Utc::now(),
            signature_hex: Some("sig".into()),
        }
    }

    fn make_log() -> CtLogConfig {
        CtLogConfig {
            log_id: "log-1".into(),
            url: "https://ct.example.com/log".into(),
            public_key_hex: "pubkey".into(),
            max_entry_size: 1024,
        }
    }

    #[test]
    fn queue_and_process() {
        let client = CtClient::new(make_log());
        client.queue_entry(make_entry("a".repeat(64)));
        client.queue_entry(make_entry("b".repeat(64)));
        assert_eq!(client.pending_count(), 2);
        let results = client.process_pending();
        assert_eq!(results.len(), 2);
        assert_eq!(client.pending_count(), 0);
    }

    #[test]
    fn accepted_entries_have_sct() {
        let client = CtClient::new(make_log());
        client.queue_entry(make_entry("a".repeat(64)));
        let results = client.process_pending();
        assert!(results[0].sct_hex.is_some());
    }

    #[test]
    fn oversized_entries_rejected() {
        let client = CtClient::new(make_log());
        let oversized = "a".repeat(3000);
        client.queue_entry(make_entry(&oversized));
        let results = client.process_pending();
        assert!(matches!(results[0].status, CtSubmissionStatus::Rejected { .. }));
    }

    #[test]
    fn inclusion_proof_generated() {
        let client = CtClient::new(make_log());
        let proof = client.inclusion_proof("hash123");
        assert_eq!(proof.len(), 1);
        assert!(proof[0].contains("hash123"));
    }

    #[test]
    fn entry_serializes() {
        let entry = make_entry("a".repeat(64));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("confium-test"));
    }

    #[test]
    fn status_serialization() {
        let status = CtSubmissionStatus::Pending;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pending\"");
    }
}
