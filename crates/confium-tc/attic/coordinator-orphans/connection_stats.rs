//! Connection statistics — per-signer operational telemetry.
//!
//! Tracks connect time, message counts, bytes transferred, last
//! activity, and error count for each connected signer. Queryable for
//! monitoring dashboards and debugging.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

/// Statistics for a single signer connection.
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Signer identity.
    pub signer_id: String,
    /// When the connection was established.
    pub connected_at: DateTime<Utc>,
    /// Total messages received from this signer.
    pub messages_received: u64,
    /// Total messages sent to this signer.
    pub messages_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Number of errors encountered.
    pub error_count: u64,
    /// Last activity timestamp.
    pub last_activity: DateTime<Utc>,
}

impl ConnectionStats {
    /// Create a new stats entry for a signer, connected now.
    pub fn new(signer_id: &str) -> Self {
        let now = Utc::now();
        Self {
            signer_id: signer_id.into(),
            connected_at: now,
            messages_received: 0,
            messages_sent: 0,
            bytes_received: 0,
            bytes_sent: 0,
            error_count: 0,
            last_activity: now,
        }
    }

    /// Record a received message.
    pub fn record_received(&mut self, bytes: u64) {
        self.messages_received += 1;
        self.bytes_received += bytes;
        self.last_activity = Utc::now();
    }

    /// Record a sent message.
    pub fn record_sent(&mut self, bytes: u64) {
        self.messages_sent += 1;
        self.bytes_sent += bytes;
        self.last_activity = Utc::now();
    }

    /// Record an error.
    pub fn record_error(&mut self) {
        self.error_count += 1;
        self.last_activity = Utc::now();
    }

    /// Connection duration in seconds.
    pub fn connection_duration_secs(&self) -> i64 {
        (Utc::now() - self.connected_at).num_seconds()
    }

    /// Total messages (sent + received).
    pub fn total_messages(&self) -> u64 {
        self.messages_received + self.messages_sent
    }

    /// Total bytes transferred.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_received + self.bytes_sent
    }
}

/// Registry of per-signer connection statistics. Thread-safe.
#[derive(Default)]
pub struct ConnectionStatsRegistry {
    entries: Mutex<HashMap<String, ConnectionStats>>,
}

impl ConnectionStatsRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new signer connection. Overwrites any existing
    /// stats for this signer_id.
    pub fn register(&self, signer_id: &str) {
        self.entries
            .lock()
            .unwrap()
            .insert(signer_id.into(), ConnectionStats::new(signer_id));
    }

    /// Record a received message for a signer.
    pub fn record_received(&self, signer_id: &str, bytes: u64) {
        if let Some(stats) = self.entries.lock().unwrap().get_mut(signer_id) {
            stats.record_received(bytes);
        }
    }

    /// Record a sent message for a signer.
    pub fn record_sent(&self, signer_id: &str, bytes: u64) {
        if let Some(stats) = self.entries.lock().unwrap().get_mut(signer_id) {
            stats.record_sent(bytes);
        }
    }

    /// Record an error for a signer.
    pub fn record_error(&self, signer_id: &str) {
        if let Some(stats) = self.entries.lock().unwrap().get_mut(signer_id) {
            stats.record_error();
        }
    }

    /// Get stats for a specific signer.
    pub fn get(&self, signer_id: &str) -> Option<ConnectionStats> {
        self.entries.lock().unwrap().get(signer_id).cloned()
    }

    /// Get stats for all signers.
    pub fn all(&self) -> Vec<ConnectionStats> {
        self.entries.lock().unwrap().values().cloned().collect()
    }

    /// Remove a signer's stats (on disconnect).
    pub fn remove(&self, signer_id: &str) {
        self.entries.lock().unwrap().remove(signer_id);
    }

    /// Number of tracked signers.
    pub fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Clear all stats.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stats_starts_at_zero() {
        let stats = ConnectionStats::new("s1");
        assert_eq!(stats.signer_id, "s1");
        assert_eq!(stats.messages_received, 0);
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.error_count, 0);
    }

    #[test]
    fn record_received_increments() {
        let mut stats = ConnectionStats::new("s1");
        stats.record_received(100);
        stats.record_received(50);
        assert_eq!(stats.messages_received, 2);
        assert_eq!(stats.bytes_received, 150);
    }

    #[test]
    fn record_sent_increments() {
        let mut stats = ConnectionStats::new("s1");
        stats.record_sent(200);
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.bytes_sent, 200);
    }

    #[test]
    fn record_error_increments() {
        let mut stats = ConnectionStats::new("s1");
        stats.record_error();
        stats.record_error();
        assert_eq!(stats.error_count, 2);
    }

    #[test]
    fn total_messages_and_bytes() {
        let mut stats = ConnectionStats::new("s1");
        stats.record_received(100);
        stats.record_sent(200);
        assert_eq!(stats.total_messages(), 2);
        assert_eq!(stats.total_bytes(), 300);
    }

    #[test]
    fn connection_duration_positive() {
        let stats = ConnectionStats::new("s1");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(stats.connection_duration_secs() >= 0);
    }

    #[test]
    fn registry_register_and_get() {
        let reg = ConnectionStatsRegistry::new();
        reg.register("s1");
        let stats = reg.get("s1").unwrap();
        assert_eq!(stats.signer_id, "s1");
        assert_eq!(stats.messages_received, 0);
    }

    #[test]
    fn registry_record_received() {
        let reg = ConnectionStatsRegistry::new();
        reg.register("s1");
        reg.record_received("s1", 500);
        let stats = reg.get("s1").unwrap();
        assert_eq!(stats.messages_received, 1);
        assert_eq!(stats.bytes_received, 500);
    }

    #[test]
    fn registry_record_sent() {
        let reg = ConnectionStatsRegistry::new();
        reg.register("s1");
        reg.record_sent("s1", 1000);
        assert_eq!(reg.get("s1").unwrap().bytes_sent, 1000);
    }

    #[test]
    fn registry_record_error() {
        let reg = ConnectionStatsRegistry::new();
        reg.register("s1");
        reg.record_error("s1");
        assert_eq!(reg.get("s1").unwrap().error_count, 1);
    }

    #[test]
    fn registry_all_returns_all_signers() {
        let reg = ConnectionStatsRegistry::new();
        reg.register("s1");
        reg.register("s2");
        reg.register("s3");
        assert_eq!(reg.all().len(), 3);
    }

    #[test]
    fn registry_remove() {
        let reg = ConnectionStatsRegistry::new();
        reg.register("s1");
        reg.remove("s1");
        assert!(reg.get("s1").is_none());
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn registry_unknown_signer_no_op() {
        let reg = ConnectionStatsRegistry::new();
        reg.record_received("unknown", 100);
        assert_eq!(reg.count(), 0);
    }
}
