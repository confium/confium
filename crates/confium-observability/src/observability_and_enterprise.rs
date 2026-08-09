//! Observability + security assurance + data management + enterprise integration.
//!
//! Trace correlation, structured logging, metric cardinality, RNG testing,
//! zeroization audit, encrypted backup, retention, replication, KMS, syslog.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// === Distributed Trace Correlation ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub baggage: HashMap<String, String>,
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceContext {
    pub fn new() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut trace_bytes = [0u8; 16];
        let mut span_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut trace_bytes);
        OsRng.fill_bytes(&mut span_bytes);
        Self {
            trace_id: hex::encode(trace_bytes),
            span_id: hex::encode(span_bytes),
            parent_span_id: None,
            baggage: HashMap::new(),
        }
    }

    pub fn child(&self) -> Self {
        use rand_core::{OsRng, RngCore};
        let mut span_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut span_bytes);
        Self {
            trace_id: self.trace_id.clone(),
            span_id: hex::encode(span_bytes),
            parent_span_id: Some(self.span_id.clone()),
            baggage: self.baggage.clone(),
        }
    }

    pub fn to_w3c_header(&self) -> String {
        format!("00-{}-{}-01", self.trace_id, self.span_id)
    }

    pub fn from_w3c_header(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        Some(Self {
            trace_id: parts[1].into(),
            span_id: parts[2].into(),
            parent_span_id: None,
            baggage: HashMap::new(),
        })
    }

    pub fn add_baggage(&mut self, key: &str, value: &str) {
        self.baggage.insert(key.into(), value.into());
    }
}

// === Structured JSON Logging ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub fields: HashMap<String, String>,
    pub trace_id: Option<String>,
}

impl LogEntry {
    pub fn info(msg: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            level: "info".into(),
            message: msg.into(),
            fields: HashMap::new(),
            trace_id: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            level: "error".into(),
            message: msg.into(),
            fields: HashMap::new(),
            trace_id: None,
        }
    }

    pub fn warn(msg: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            level: "warn".into(),
            message: msg.into(),
            fields: HashMap::new(),
            trace_id: None,
        }
    }

    pub fn field(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    pub fn with_trace(mut self, trace_id: &str) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn to_jsonl(&self) -> String {
        self.to_json() + "\n"
    }
}

#[derive(Default)]
pub struct StructuredLogger {
    entries: Mutex<Vec<LogEntry>>,
    min_level: Mutex<String>,
}

impl StructuredLogger {
    pub fn new(min_level: &str) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            min_level: Mutex::new(min_level.into()),
        }
    }

    pub fn log(&self, entry: LogEntry) {
        let levels = ["trace", "debug", "info", "warn", "error"];
        let min_idx = levels
            .iter()
            .position(|&l| l == *self.min_level.lock().unwrap())
            .unwrap_or(2);
        let entry_idx = levels
            .iter()
            .position(|&l| l == entry.level.as_str())
            .unwrap_or(2);
        if entry_idx >= min_idx {
            self.entries.lock().unwrap().push(entry);
        }
    }

    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().unwrap().clone()
    }
    pub fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
    pub fn to_jsonl(&self) -> String {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.to_jsonl())
            .collect()
    }
    pub fn flush(&self) -> Vec<LogEntry> {
        let mut entries = self.entries.lock().unwrap();
        std::mem::take(&mut *entries)
    }
}

// === Metric Cardinality Limiter ===

pub struct CardinalityLimiter {
    label_counts: Mutex<HashMap<String, HashSet<String>>>,
    max_values_per_label: usize,
    total_series: AtomicU64,
    max_total_series: u64,
}

impl CardinalityLimiter {
    pub fn new(max_values_per_label: usize, max_total_series: u64) -> Self {
        Self {
            label_counts: Mutex::new(HashMap::new()),
            max_values_per_label,
            total_series: AtomicU64::new(0),
            max_total_series,
        }
    }

    pub fn allow_label(&self, label_name: &str, label_value: &str) -> bool {
        if self.total_series.load(Ordering::SeqCst) >= self.max_total_series {
            return false;
        }
        let mut counts = self.label_counts.lock().unwrap();
        let values = counts.entry(label_name.into()).or_default();
        if values.contains(label_value) {
            return true;
        }
        if values.len() >= self.max_values_per_label {
            return false;
        }
        values.insert(label_value.into());
        self.total_series.fetch_add(1, Ordering::SeqCst);
        true
    }

    pub fn label_value_count(&self, label: &str) -> usize {
        self.label_counts
            .lock()
            .unwrap()
            .get(label)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    pub fn total_series(&self) -> u64 {
        self.total_series.load(Ordering::SeqCst)
    }
    pub fn reset(&self) {
        self.label_counts.lock().unwrap().clear();
        self.total_series.store(0, Ordering::SeqCst);
    }
}

// === RNG Statistical Testing (NIST SP 800-22 simplified) ===

pub fn frequency_test(data: &[u8]) -> f64 {
    let n = data.len() as f64 * 8.0;
    let mut s: f64 = 0.0;
    for byte in data {
        for bit in 0..8 {
            s += if (byte >> bit) & 1 == 1 { 1.0 } else { -1.0 };
        }
    }
    let s_obs = s.abs() / n.sqrt();
    erfc(s_obs / 2f64.sqrt())
}

pub fn runs_test(data: &[u8]) -> f64 {
    let bits: Vec<i8> = data
        .iter()
        .flat_map(|b| (0..8).map(move |i| ((b >> i) & 1) as i8))
        .collect();
    let n = bits.len() as f64;
    let pi: f64 = bits.iter().map(|&b| b as f64).sum::<f64>() / n;
    if (pi - 0.5).abs() >= 2.0 / n.sqrt() {
        return 0.0;
    }
    let mut v_obs = 1.0;
    for i in 1..bits.len() {
        if bits[i] != bits[i - 1] {
            v_obs += 1.0;
        }
    }
    let denom = 2.0 * pi * (1.0 - pi);
    let s = (2.0 * (n.sqrt())) * denom;
    erfc((v_obs - s) / (2.0 * s * denom.sqrt()))
}

pub fn entropy_estimate(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn erfc(x: f64) -> f64 {
    // Approximate complementary error function
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let r = t
        * (-z * z - 1.26551223
            + t * (1.00002368
                + t * (-0.37609177
                    + t * (0.36496351
                        + t * (-0.16108111 + t * (0.08095456 + t * (-0.02907307)))))))
            .exp();
    if x >= 0.0 { r } else { 2.0 - r }
}

// === Memory Zeroization Audit ===

pub struct ZeroizationAuditor {
    tracked_secrets: Mutex<Vec<SecretRecord>>,
}

#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub id: String,
    pub allocated_at: DateTime<Utc>,
    pub zeroized: bool,
    pub size_bytes: usize,
}

impl ZeroizationAuditor {
    pub fn new() -> Self {
        Self {
            tracked_secrets: Mutex::new(Vec::new()),
        }
    }

    pub fn track(&self, id: &str, size: usize) {
        self.tracked_secrets.lock().unwrap().push(SecretRecord {
            id: id.into(),
            allocated_at: Utc::now(),
            zeroized: false,
            size_bytes: size,
        });
    }

    pub fn mark_zeroized(&self, id: &str) {
        if let Some(s) = self
            .tracked_secrets
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| s.id == id)
        {
            s.zeroized = true;
        }
    }

    pub fn unzeroized_count(&self) -> usize {
        self.tracked_secrets
            .lock()
            .unwrap()
            .iter()
            .filter(|s| !s.zeroized)
            .count()
    }

    pub fn audit_report(&self) -> ZeroizationReport {
        let secrets = self.tracked_secrets.lock().unwrap();
        let total = secrets.len();
        let zeroized = secrets.iter().filter(|s| s.zeroized).count();
        ZeroizationReport {
            total_secrets: total,
            zeroized,
            unzeroized: total - zeroized,
        }
    }
}

impl Default for ZeroizationAuditor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroizationReport {
    pub total_secrets: usize,
    pub zeroized: usize,
    pub unzeroized: usize,
}

// === Encrypted Share Backup ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBackup {
    pub backup_id: String,
    pub encrypted_shares_hex: Vec<String>,
    pub backup_key_threshold: u32,
    pub created_at: DateTime<Utc>,
}

pub struct BackupManager {
    backups: Mutex<HashMap<String, EncryptedBackup>>,
}

impl BackupManager {
    pub fn new() -> Self {
        Self {
            backups: Mutex::new(HashMap::new()),
        }
    }

    pub fn create_backup(
        &self,
        backup_id: &str,
        shares: &[Vec<u8>],
        threshold: u32,
    ) -> EncryptedBackup {
        use rand_core::{OsRng, RngCore};
        let encrypted: Vec<String> = shares
            .iter()
            .map(|s| {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                let encrypted: Vec<u8> = s
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key[i % key.len()])
                    .collect();
                hex::encode(encrypted)
            })
            .collect();
        let backup = EncryptedBackup {
            backup_id: backup_id.into(),
            encrypted_shares_hex: encrypted,
            backup_key_threshold: threshold,
            created_at: Utc::now(),
        };
        self.backups
            .lock()
            .unwrap()
            .insert(backup_id.into(), backup.clone());
        backup
    }

    pub fn restore_backup(&self, backup_id: &str, keys: &[[u8; 32]; 32]) -> Option<Vec<Vec<u8>>> {
        let backups = self.backups.lock().unwrap();
        let backup = backups.get(backup_id)?;
        if keys.len() < backup.backup_key_threshold as usize {
            return None;
        }
        // Simplified restore: XOR with keys (mock)
        let restored: Vec<Vec<u8>> = backup
            .encrypted_shares_hex
            .iter()
            .map(|hex_str| {
                let encrypted = hex::decode(hex_str).unwrap_or_default();
                let key = &keys[0];
                encrypted
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key[i % key.len()])
                    .collect()
            })
            .collect();
        Some(restored)
    }

    pub fn backup_count(&self) -> usize {
        self.backups.lock().unwrap().len()
    }
    pub fn list_backups(&self) -> Vec<String> {
        self.backups.lock().unwrap().keys().cloned().collect()
    }
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}

// === Data Retention Policy Engine ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub session_retention_days: u32,
    pub audit_retention_days: u32,
    pub wal_retention_entries: u64,
    pub purge_interval_hours: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            session_retention_days: 7,
            audit_retention_days: 365,
            wal_retention_entries: 100_000,
            purge_interval_hours: 1,
        }
    }
}

pub struct RetentionEngine {
    policy: RetentionPolicy,
    purged_sessions: AtomicU64,
    purged_audit_entries: AtomicU64,
    last_purge: Mutex<Option<DateTime<Utc>>>,
}

impl RetentionEngine {
    pub fn new(policy: RetentionPolicy) -> Self {
        Self {
            policy,
            purged_sessions: AtomicU64::new(0),
            purged_audit_entries: AtomicU64::new(0),
            last_purge: Mutex::new(None),
        }
    }

    pub fn should_purge(&self) -> bool {
        if let Some(last) = *self.last_purge.lock().unwrap() {
            Utc::now() - last >= Duration::hours(self.policy.purge_interval_hours as i64)
        } else {
            true
        }
    }

    pub fn purge_sessions(&self, sessions: &mut Vec<(String, DateTime<Utc>)>) -> usize {
        let cutoff = Utc::now() - Duration::days(self.policy.session_retention_days as i64);
        let before = sessions.len();
        sessions.retain(|(_, ts)| *ts > cutoff);
        let purged = before - sessions.len();
        self.purged_sessions
            .fetch_add(purged as u64, Ordering::SeqCst);
        *self.last_purge.lock().unwrap() = Some(Utc::now());
        purged
    }

    pub fn truncate_wal(&self, wal: &mut Vec<String>) -> usize {
        let max = self.policy.wal_retention_entries as usize;
        if wal.len() <= max {
            return 0;
        }
        let excess = wal.len() - max;
        wal.drain(..excess);
        self.purged_audit_entries
            .fetch_add(excess as u64, Ordering::SeqCst);
        excess
    }

    pub fn total_purged_sessions(&self) -> u64 {
        self.purged_sessions.load(Ordering::SeqCst)
    }
    pub fn total_purged_entries(&self) -> u64 {
        self.purged_audit_entries.load(Ordering::SeqCst)
    }
}

// === Cross-Region Replication ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaState {
    pub region: String,
    pub last_seq: u64,
    pub last_sync: DateTime<Utc>,
    pub lag_seconds: i64,
}

pub struct ReplicationManager {
    replicas: Mutex<HashMap<String, ReplicaState>>,
    local_seq: AtomicU64,
}

impl ReplicationManager {
    pub fn new() -> Self {
        Self {
            replicas: Mutex::new(HashMap::new()),
            local_seq: AtomicU64::new(0),
        }
    }

    pub fn register_replica(&self, region: &str) {
        self.replicas.lock().unwrap().insert(
            region.into(),
            ReplicaState {
                region: region.into(),
                last_seq: 0,
                last_sync: Utc::now(),
                lag_seconds: 0,
            },
        );
    }

    pub fn record_replication(&self, region: &str, seq: u64) {
        let mut replicas = self.replicas.lock().unwrap();
        if let Some(r) = replicas.get_mut(region) {
            r.last_seq = seq;
            r.last_sync = Utc::now();
            let _local = self.local_seq.load(Ordering::SeqCst);
            r.lag_seconds = (Utc::now() - r.last_sync).num_seconds();
        }
    }

    pub fn advance_local(&self) -> u64 {
        self.local_seq.fetch_add(1, Ordering::SeqCst) + 1
    }
    pub fn local_seq(&self) -> u64 {
        self.local_seq.load(Ordering::SeqCst)
    }

    pub fn replica_lag(&self, region: &str) -> Option<u64> {
        let replicas = self.replicas.lock().unwrap();
        let r = replicas.get(region)?;
        Some(self.local_seq.load(Ordering::SeqCst) - r.last_seq)
    }

    pub fn replica_count(&self) -> usize {
        self.replicas.lock().unwrap().len()
    }
    pub fn all_replicas(&self) -> Vec<ReplicaState> {
        self.replicas.lock().unwrap().values().cloned().collect()
    }
}

impl Default for ReplicationManager {
    fn default() -> Self {
        Self::new()
    }
}

// === Cloud KMS Integration Trait ===

pub trait CloudKms: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], key_id: &str) -> Result<Vec<u8>, String>;
    fn decrypt(&self, ciphertext: &[u8], key_id: &str) -> Result<Vec<u8>, String>;
    fn create_key(&self, key_id: &str) -> Result<(), String>;
    fn delete_key(&self, key_id: &str) -> Result<(), String>;
    fn key_exists(&self, key_id: &str) -> bool;
    fn name(&self) -> &str;
}

pub struct MockKms {
    keys: Mutex<HashMap<String, [u8; 32]>>,
}

impl MockKms {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
}

impl CloudKms for MockKms {
    fn encrypt(&self, plaintext: &[u8], key_id: &str) -> Result<Vec<u8>, String> {
        let keys = self.keys.lock().unwrap();
        let key = keys.get(key_id).ok_or("key not found")?;
        Ok(plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 32])
            .collect())
    }
    fn decrypt(&self, ciphertext: &[u8], key_id: &str) -> Result<Vec<u8>, String> {
        self.encrypt(ciphertext, key_id) // XOR is symmetric
    }
    fn create_key(&self, key_id: &str) -> Result<(), String> {
        use rand_core::{OsRng, RngCore};
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        self.keys.lock().unwrap().insert(key_id.into(), key);
        Ok(())
    }
    fn delete_key(&self, key_id: &str) -> Result<(), String> {
        self.keys.lock().unwrap().remove(key_id);
        Ok(())
    }
    fn key_exists(&self, key_id: &str) -> bool {
        self.keys.lock().unwrap().contains_key(key_id)
    }
    fn name(&self) -> &str {
        "mock-kms"
    }
}

impl Default for MockKms {
    fn default() -> Self {
        Self::new()
    }
}

// === Syslog Forwarding ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogMessage {
    pub facility: u8,
    pub severity: u8,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub app_name: String,
    pub proc_id: u32,
    pub msg_id: String,
    pub message: String,
}

impl SyslogMessage {
    pub fn new(severity: u8, message: &str) -> Self {
        Self {
            facility: 4,
            severity,
            timestamp: Utc::now(),
            hostname: "confium".into(),
            app_name: "coordinator".into(),
            proc_id: 1,
            msg_id: "audit".into(),
            message: message.into(),
        }
    }

    pub fn priority(&self) -> u8 {
        self.facility * 8 + self.severity
    }

    pub fn to_rfc5424(&self) -> String {
        format!(
            "<{}>1 {} {} {} {} {} {}",
            self.priority(),
            self.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            self.hostname,
            self.app_name,
            self.proc_id,
            self.msg_id,
            self.message
        )
    }
}

#[derive(Default)]
pub struct SyslogForwarder {
    sent: Mutex<Vec<SyslogMessage>>,
    enabled: Mutex<bool>,
}

impl SyslogForwarder {
    pub fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            enabled: Mutex::new(true),
        }
    }

    pub fn forward(&self, msg: SyslogMessage) -> bool {
        if !*self.enabled.lock().unwrap() {
            return false;
        }
        self.sent.lock().unwrap().push(msg);
        true
    }

    pub fn forward_audit(&self, event: &str) -> bool {
        self.forward(SyslogMessage::new(5, event)) // 5 = notice
    }

    pub fn forward_error(&self, error: &str) -> bool {
        self.forward(SyslogMessage::new(3, error)) // 3 = error
    }

    pub fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.lock().unwrap() = enabled;
    }
    pub fn messages(&self) -> Vec<SyslogMessage> {
        self.sent.lock().unwrap().clone()
    }
    pub fn flush(&self) -> Vec<SyslogMessage> {
        let mut sent = self.sent.lock().unwrap();
        std::mem::take(&mut *sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trace correlation
    #[test]
    fn trace_context_child_inherits_trace_id() {
        let parent = TraceContext::new();
        let child = parent.child();
        assert_eq!(parent.trace_id, child.trace_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id.clone()));
    }

    #[test]
    fn trace_w3c_header_round_trips() {
        let ctx = TraceContext::new();
        let header = ctx.to_w3c_header();
        let parsed = TraceContext::from_w3c_header(&header).unwrap();
        assert_eq!(ctx.trace_id, parsed.trace_id);
    }

    #[test]
    fn trace_baggage() {
        let mut ctx = TraceContext::new();
        ctx.add_baggage("user", "alice");
        let child = ctx.child();
        assert_eq!(child.baggage.get("user"), Some(&"alice".to_string()));
    }

    // Structured logging
    #[test]
    fn log_entry_to_json() {
        let entry = LogEntry::info("test message").field("key", "value");
        let json = entry.to_json();
        assert!(json.contains("test message"));
        assert!(json.contains("\"key\":\"value\""));
    }

    #[test]
    fn logger_filters_by_level() {
        let logger = StructuredLogger::new("warn");
        logger.log(LogEntry::info("info msg"));
        logger.log(LogEntry::warn("warn msg"));
        logger.log(LogEntry::error("error msg"));
        assert_eq!(logger.count(), 2); // info filtered out
    }

    #[test]
    fn logger_jsonl_output() {
        let logger = StructuredLogger::new("info");
        logger.log(LogEntry::info("msg1"));
        logger.log(LogEntry::info("msg2"));
        let jsonl = logger.to_jsonl();
        assert!(jsonl.contains("msg1"));
        assert!(jsonl.contains("msg2"));
    }

    // Metric cardinality
    #[test]
    fn cardinality_allows_new_values() {
        let limiter = CardinalityLimiter::new(5, 100);
        assert!(limiter.allow_label("user", "alice"));
        assert!(limiter.allow_label("user", "bob"));
        assert_eq!(limiter.label_value_count("user"), 2);
    }

    #[test]
    fn cardinality_rejects_excess() {
        let limiter = CardinalityLimiter::new(2, 100);
        assert!(limiter.allow_label("ip", "1.1.1.1"));
        assert!(limiter.allow_label("ip", "2.2.2.2"));
        assert!(!limiter.allow_label("ip", "3.3.3.3"));
    }

    #[test]
    fn cardinality_total_series_limit() {
        let limiter = CardinalityLimiter::new(100, 3);
        limiter.allow_label("a", "1");
        limiter.allow_label("a", "2");
        limiter.allow_label("a", "3");
        assert_eq!(limiter.total_series(), 3);
        assert!(!limiter.allow_label("a", "4"));
    }

    // RNG testing
    #[test]
    fn frequency_test_random_data() {
        use rand_core::RngCore;
        let mut data = vec![0u8; 1000];
        rand_core::OsRng.fill_bytes(&mut data);
        let p_value = frequency_test(&data);
        // p-value threshold 0.001 (1 in 1000) — at 0.01 the test would
        // flap ~1% of runs by definition. Even at 0.001 the test is
        // probabilistic; treat values in the borderline range as
        // informational rather than a hard failure.
        if p_value <= 0.001 {
            panic!("p-value {p_value} is far below the random-data expectation");
        }
    }

    #[test]
    fn frequency_test_all_zeros() {
        let data = vec![0u8; 100];
        let p_value = frequency_test(&data);
        assert!(p_value < 0.01, "p-value should be < 0.01 for all-zeros");
    }

    #[test]
    fn entropy_random_is_high() {
        use rand_core::RngCore;
        let mut data = vec![0u8; 1000];
        rand_core::OsRng.fill_bytes(&mut data);
        let entropy = entropy_estimate(&data);
        assert!(
            entropy > 7.0,
            "entropy should be > 7.0 bits/byte for random data"
        );
    }

    #[test]
    fn entropy_constant_is_low() {
        let data = vec![0x42u8; 1000];
        let entropy = entropy_estimate(&data);
        assert!(entropy < 1.0);
    }

    // Zeroization audit
    #[test]
    fn audit_tracks_secrets() {
        let auditor = ZeroizationAuditor::new();
        auditor.track("s1", 32);
        auditor.track("s2", 64);
        assert_eq!(auditor.unzeroized_count(), 2);
        auditor.mark_zeroized("s1");
        assert_eq!(auditor.unzeroized_count(), 1);
    }

    #[test]
    fn audit_report() {
        let auditor = ZeroizationAuditor::new();
        auditor.track("s1", 32);
        auditor.track("s2", 64);
        auditor.mark_zeroized("s1");
        let report = auditor.audit_report();
        assert_eq!(report.total_secrets, 2);
        assert_eq!(report.zeroized, 1);
        assert_eq!(report.unzeroized, 1);
    }

    // Encrypted backup
    #[test]
    fn backup_create_and_list() {
        let mgr = BackupManager::new();
        mgr.create_backup("b1", &[vec![0xAA; 32], vec![0xBB; 32]], 2);
        assert_eq!(mgr.backup_count(), 1);
        assert!(mgr.list_backups().contains(&"b1".to_string()));
    }

    // Retention
    #[test]
    fn retention_purges_old_sessions() {
        let engine = RetentionEngine::new(RetentionPolicy {
            session_retention_days: 1,
            ..Default::default()
        });
        let mut sessions = vec![
            ("s1".into(), Utc::now() - Duration::days(5)),
            ("s2".into(), Utc::now()),
        ];
        let purged = engine.purge_sessions(&mut sessions);
        assert_eq!(purged, 1);
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn retention_truncates_wal() {
        let engine = RetentionEngine::new(RetentionPolicy {
            wal_retention_entries: 5,
            ..Default::default()
        });
        let mut wal: Vec<String> = (0..10).map(|i| format!("entry-{i}")).collect();
        let purged = engine.truncate_wal(&mut wal);
        assert_eq!(purged, 5);
        assert_eq!(wal.len(), 5);
    }

    // Replication
    #[test]
    fn replication_tracks_lag() {
        let mgr = ReplicationManager::new();
        mgr.register_replica("us-east");
        mgr.advance_local();
        mgr.advance_local();
        mgr.advance_local();
        mgr.record_replication("us-east", 1);
        assert_eq!(mgr.replica_lag("us-east"), Some(2));
    }

    #[test]
    fn replication_multiple_regions() {
        let mgr = ReplicationManager::new();
        mgr.register_replica("us-east");
        mgr.register_replica("eu-west");
        assert_eq!(mgr.replica_count(), 2);
    }

    // KMS
    #[test]
    fn kms_encrypt_decrypt() {
        let kms = MockKms::new();
        kms.create_key("key1").unwrap();
        let ct = kms.encrypt(b"secret", "key1").unwrap();
        let pt = kms.decrypt(&ct, "key1").unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn kms_key_exists() {
        let kms = MockKms::new();
        assert!(!kms.key_exists("k1"));
        kms.create_key("k1").unwrap();
        assert!(kms.key_exists("k1"));
        kms.delete_key("k1").unwrap();
        assert!(!kms.key_exists("k1"));
    }

    // Syslog
    #[test]
    fn syslog_format_rfc5424() {
        let msg = SyslogMessage::new(5, "test event");
        let formatted = msg.to_rfc5424();
        assert!(formatted.starts_with("<"));
        assert!(formatted.contains("test event"));
    }

    #[test]
    fn syslog_forward_audit() {
        let fwd = SyslogForwarder::new();
        fwd.forward_audit("session created");
        fwd.forward_error("signing failed");
        assert_eq!(fwd.sent_count(), 2);
    }

    #[test]
    fn syslog_disabled() {
        let fwd = SyslogForwarder::new();
        fwd.set_enabled(false);
        fwd.forward_audit("test");
        assert_eq!(fwd.sent_count(), 0);
    }

    #[test]
    fn syslog_flush() {
        let fwd = SyslogForwarder::new();
        fwd.forward_audit("msg1");
        fwd.forward_audit("msg2");
        let flushed = fwd.flush();
        assert_eq!(flushed.len(), 2);
        assert_eq!(fwd.sent_count(), 0);
    }
}
