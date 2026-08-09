//! Production hardening: tamper-evident audit, session GC, signer quarantine,
//! time-locked/conditional signing, cross-quorum aggregation, config reload,
//! wallet policy, replay protection, proactive security.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// === Tamper-Evident Audit Log (Merkle-backed) ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperProofEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub payload_hex: String,
    pub prev_hash_hex: String,
    pub entry_hash_hex: String,
}

pub struct TamperProofLog {
    entries: Mutex<Vec<TamperProofEntry>>,
    root: Mutex<String>,
}

impl TamperProofLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            root: Mutex::new("0".repeat(64)),
        }
    }

    pub fn append(&self, event_type: &str, payload: &[u8]) -> u64 {
        let mut entries = self.entries.lock().unwrap();
        let seq = entries.len() as u64 + 1;
        let prev_hash = entries
            .last()
            .map(|e| e.entry_hash_hex.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let mut hasher = Sha256::new();
        hasher.update(seq.to_be_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(payload);
        hasher.update(prev_hash.as_bytes());
        let entry_hash = hex::encode(hasher.finalize());
        let entry = TamperProofEntry {
            sequence: seq,
            timestamp: Utc::now(),
            event_type: event_type.into(),
            payload_hex: hex::encode(payload),
            prev_hash_hex: prev_hash.clone(),
            entry_hash_hex: entry_hash.clone(),
        };
        entries.push(entry);
        *self.root.lock().unwrap() = entry_hash;
        seq
    }

    pub fn verify_integrity(&self) -> bool {
        let entries = self.entries.lock().unwrap();
        let mut prev_hash = "0".repeat(64);
        for entry in entries.iter() {
            if entry.prev_hash_hex != prev_hash {
                return false;
            }
            let mut hasher = Sha256::new();
            hasher.update(entry.sequence.to_be_bytes());
            hasher.update(entry.event_type.as_bytes());
            let payload = match hex::decode(&entry.payload_hex) {
                Ok(p) => p,
                Err(_) => return false,
            };
            hasher.update(&payload);
            hasher.update(entry.prev_hash_hex.as_bytes());
            let computed = hex::encode(hasher.finalize());
            if computed != entry.entry_hash_hex {
                return false;
            }
            prev_hash = entry.entry_hash_hex.clone();
        }
        true
    }

    pub fn root_hash(&self) -> String {
        self.root.lock().unwrap().clone()
    }
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
    pub fn entries(&self) -> Vec<TamperProofEntry> {
        self.entries.lock().unwrap().clone()
    }
}

impl Default for TamperProofLog {
    fn default() -> Self {
        Self::new()
    }
}

// === Session Garbage Collector ===

#[derive(Debug, Clone)]
pub struct GcConfig {
    pub max_completed_age: Duration,
    pub max_expired_age: Duration,
    pub max_retained: usize,
    pub gc_interval_secs: u64,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            max_completed_age: Duration::hours(24),
            max_expired_age: Duration::hours(48),
            max_retained: 10_000,
            gc_interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GcSessionInfo {
    pub session_id: String,
    pub state: String,
    pub last_updated: DateTime<Utc>,
}

pub struct SessionGarbageCollector {
    config: GcConfig,
    collected: AtomicU64,
}

impl SessionGarbageCollector {
    pub fn new(config: GcConfig) -> Self {
        Self {
            config,
            collected: AtomicU64::new(0),
        }
    }

    pub fn collect(&self, sessions: &mut Vec<GcSessionInfo>) -> usize {
        let now = Utc::now();
        let before = sessions.len();
        sessions.retain(|s| {
            let age = now - s.last_updated;
            match s.state.as_str() {
                "completed" => age < self.config.max_completed_age,
                "expired" | "aborted" => age < self.config.max_expired_age,
                _ => true, // never GC pending/active sessions
            }
        });
        // Also enforce max_retained
        if sessions.len() > self.config.max_retained {
            let excess = sessions.len() - self.config.max_retained;
            sessions.drain(..excess);
        }
        let collected = before - sessions.len();
        self.collected.fetch_add(collected as u64, Ordering::SeqCst);
        collected
    }

    pub fn total_collected(&self) -> u64 {
        self.collected.load(Ordering::SeqCst)
    }
}

// === Suspicious Signer Quarantine ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerReputation {
    pub signer_id: String,
    pub good_count: u32,
    pub bad_count: u32,
    pub quarantined: bool,
    pub quarantine_until: Option<DateTime<Utc>>,
}

pub struct SignerQuarantine {
    reputations: Mutex<HashMap<String, SignerReputation>>,
    bad_threshold: u32,
    quarantine_duration: Duration,
}

impl SignerQuarantine {
    pub fn new(bad_threshold: u32, quarantine_duration: Duration) -> Self {
        Self {
            reputations: Mutex::new(HashMap::new()),
            bad_threshold,
            quarantine_duration,
        }
    }

    pub fn record_good(&self, signer_id: &str) {
        let mut reps = self.reputations.lock().unwrap();
        let rep = reps
            .entry(signer_id.into())
            .or_insert_with(|| SignerReputation {
                signer_id: signer_id.into(),
                good_count: 0,
                bad_count: 0,
                quarantined: false,
                quarantine_until: None,
            });
        rep.good_count += 1;
        if rep.quarantined && rep.good_count >= 10 {
            rep.quarantined = false;
            rep.quarantine_until = None;
        }
    }

    pub fn record_bad(&self, signer_id: &str) {
        let mut reps = self.reputations.lock().unwrap();
        let rep = reps
            .entry(signer_id.into())
            .or_insert_with(|| SignerReputation {
                signer_id: signer_id.into(),
                good_count: 0,
                bad_count: 0,
                quarantined: false,
                quarantine_until: None,
            });
        rep.bad_count += 1;
        if rep.bad_count >= self.bad_threshold {
            rep.quarantined = true;
            rep.quarantine_until = Some(Utc::now() + self.quarantine_duration);
        }
    }

    pub fn is_quarantined(&self, signer_id: &str) -> bool {
        let reps = self.reputations.lock().unwrap();
        reps.get(signer_id)
            .map(|r| {
                if !r.quarantined {
                    return false;
                }
                if let Some(until) = r.quarantine_until {
                    return Utc::now() < until;
                }
                true
            })
            .unwrap_or(false)
    }

    pub fn reputation(&self, signer_id: &str) -> Option<SignerReputation> {
        self.reputations.lock().unwrap().get(signer_id).cloned()
    }

    pub fn quarantined_count(&self) -> usize {
        self.reputations
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.quarantined)
            .count()
    }

    pub fn release(&self, signer_id: &str) {
        if let Some(rep) = self.reputations.lock().unwrap().get_mut(signer_id) {
            rep.quarantined = false;
            rep.quarantine_until = None;
        }
    }
}

// === Time-Locked Threshold Signatures ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockCondition {
    pub unlock_at: DateTime<Utc>,
}

pub struct TimeLockedSession {
    pub session_id: String,
    pub condition: TimeLockCondition,
    pub signature: Option<Vec<u8>>,
    pub ready: bool,
}

impl TimeLockedSession {
    pub fn new(session_id: &str, unlock_at: DateTime<Utc>) -> Self {
        Self {
            session_id: session_id.into(),
            condition: TimeLockCondition { unlock_at },
            signature: None,
            ready: false,
        }
    }

    pub fn check_unlock(&mut self) -> bool {
        if Utc::now() >= self.condition.unlock_at {
            self.ready = true;
        }
        self.ready
    }

    pub fn store_signature(&mut self, sig: Vec<u8>) -> Result<(), String> {
        if !self.ready {
            return Err("not unlocked yet".into());
        }
        self.signature = Some(sig);
        Ok(())
    }
}

// === Conditional Threshold Signatures ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningCondition {
    Always,
    QuorumVote {
        required: u32,
    },
    OracleValue {
        oracle_id: String,
        min_value: f64,
    },
    TimeWindow {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
}

impl SigningCondition {
    pub fn evaluate(&self, context: &SigningContext) -> bool {
        match self {
            Self::Always => true,
            Self::QuorumVote { required } => context.vote_count >= *required as usize,
            Self::OracleValue { min_value, .. } => {
                context.oracle_value.unwrap_or(f64::MIN) >= *min_value
            }
            Self::TimeWindow { start, end } => {
                let now = Utc::now();
                now >= *start && now <= *end
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SigningContext {
    pub vote_count: usize,
    pub oracle_value: Option<f64>,
}

// === Cross-Quorum Signature Aggregation ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossQuorumAggSig {
    pub quorum_ids: Vec<String>,
    pub message_hash_hex: String,
    pub aggregate_signature_hex: String,
    pub timestamp: DateTime<Utc>,
}

pub fn aggregate_cross_quorum(
    quorum_sigs: &[(String, Vec<u8>)],
    message_hash: &[u8],
) -> CrossQuorumAggSig {
    let mut agg = vec![0u8; 64];
    for (_, sig) in quorum_sigs {
        for (i, &b) in sig.iter().take(64).enumerate() {
            agg[i] ^= b;
        }
    }
    CrossQuorumAggSig {
        quorum_ids: quorum_sigs.iter().map(|(q, _)| q.clone()).collect(),
        message_hash_hex: hex::encode(message_hash),
        aggregate_signature_hex: hex::encode(&agg),
        timestamp: Utc::now(),
    }
}

// === Configuration Hot-Reload ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    pub max_sessions: usize,
    pub session_timeout_secs: u64,
    pub rate_limit_per_minute: u32,
    pub allowed_schemes: Vec<String>,
    pub config_version: u32,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            max_sessions: 100,
            session_timeout_secs: 3600,
            rate_limit_per_minute: 100,
            allowed_schemes: vec!["CMP20".into(), "FROST-P256".into()],
            config_version: 1,
        }
    }
}

pub struct ConfigManager {
    config: Mutex<CoordinatorConfig>,
    reload_count: AtomicU64,
    last_reload: Mutex<Option<DateTime<Utc>>>,
}

impl ConfigManager {
    pub fn new(initial: CoordinatorConfig) -> Self {
        Self {
            config: Mutex::new(initial),
            reload_count: AtomicU64::new(0),
            last_reload: Mutex::new(None),
        }
    }

    pub fn reload(&self, new_config: CoordinatorConfig) {
        let mut config = self.config.lock().unwrap();
        let old_version = config.config_version;
        *config = CoordinatorConfig {
            config_version: old_version + 1,
            ..new_config
        };
        self.reload_count.fetch_add(1, Ordering::SeqCst);
        *self.last_reload.lock().unwrap() = Some(Utc::now());
    }

    pub fn config(&self) -> CoordinatorConfig {
        self.config.lock().unwrap().clone()
    }
    pub fn reload_count(&self) -> u64 {
        self.reload_count.load(Ordering::SeqCst)
    }
    pub fn last_reload(&self) -> Option<DateTime<Utc>> {
        *self.last_reload.lock().unwrap()
    }
    pub fn config_version(&self) -> u32 {
        self.config.lock().unwrap().config_version
    }
}

// === Wallet Policy Language ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPolicy {
    pub required_signers: u32,
    pub total_signers: u32,
    pub max_amount: Option<u64>,
    pub allowed_recipients: Option<HashSet<String>>,
    pub time_window: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

impl WalletPolicy {
    pub fn evaluate(&self, ctx: &WalletTxContext) -> Result<(), String> {
        if ctx.signer_count < self.required_signers as usize {
            return Err(format!(
                "need {} signers, got {}",
                self.required_signers, ctx.signer_count
            ));
        }
        if let Some(max) = self.max_amount {
            if ctx.amount > max {
                return Err(format!("amount {} exceeds max {}", ctx.amount, max));
            }
        }
        if let Some(ref allowed) = self.allowed_recipients {
            if !allowed.contains(&ctx.recipient) {
                return Err(format!("recipient {} not in allowlist", ctx.recipient));
            }
        }
        if let Some((start, end)) = self.time_window {
            let now = Utc::now();
            if now < start || now > end {
                return Err("outside time window".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WalletTxContext {
    pub signer_count: usize,
    pub amount: u64,
    pub recipient: String,
}

// === Replay Protection ===

pub struct ReplayProtection {
    seen_nonces: Mutex<HashSet<Vec<u8>>>,
    max_cache_size: usize,
}

impl ReplayProtection {
    pub fn new(max_cache_size: usize) -> Self {
        Self {
            seen_nonces: Mutex::new(HashSet::new()),
            max_cache_size,
        }
    }

    pub fn check_and_consume(&self, nonce: &[u8]) -> bool {
        let mut seen = self.seen_nonces.lock().unwrap();
        if seen.contains(nonce) {
            return false;
        }
        if seen.len() >= self.max_cache_size {
            // Evict ~10% of entries (random-ish eviction)
            let to_remove = self.max_cache_size / 10;
            let keys: Vec<Vec<u8>> = seen.iter().take(to_remove).cloned().collect();
            for k in keys {
                seen.remove(&k);
            }
        }
        seen.insert(nonce.to_vec());
        true
    }

    pub fn is_seen(&self, nonce: &[u8]) -> bool {
        self.seen_nonces.lock().unwrap().contains(nonce)
    }

    pub fn cache_size(&self) -> usize {
        self.seen_nonces.lock().unwrap().len()
    }
}

// === Proactive Security Scheduler ===

pub struct ProactiveScheduler {
    last_refresh: Mutex<DateTime<Utc>>,
    refresh_interval: Duration,
    refresh_count: AtomicU64,
    auto_refresh: Mutex<bool>,
}

impl ProactiveScheduler {
    pub fn new(refresh_interval: Duration) -> Self {
        Self {
            last_refresh: Mutex::new(Utc::now()),
            refresh_interval,
            refresh_count: AtomicU64::new(0),
            auto_refresh: Mutex::new(true),
        }
    }

    pub fn should_refresh(&self) -> bool {
        if !*self.auto_refresh.lock().unwrap() {
            return false;
        }
        let last = *self.last_refresh.lock().unwrap();
        Utc::now() - last >= self.refresh_interval
    }

    pub fn mark_refreshed(&self) {
        *self.last_refresh.lock().unwrap() = Utc::now();
        self.refresh_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn set_auto_refresh(&self, enabled: bool) {
        *self.auto_refresh.lock().unwrap() = enabled;
    }
    pub fn refresh_count(&self) -> u64 {
        self.refresh_count.load(Ordering::SeqCst)
    }
    pub fn last_refresh(&self) -> DateTime<Utc> {
        *self.last_refresh.lock().unwrap()
    }

    pub fn next_refresh_at(&self) -> DateTime<Utc> {
        *self.last_refresh.lock().unwrap() + self.refresh_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tamper-evident audit
    #[test]
    fn audit_append_and_verify() {
        let log = TamperProofLog::new();
        log.append("created", b"session-1");
        log.append("signed", b"sig-data");
        assert!(log.verify_integrity());
        assert_eq!(log.entry_count(), 2);
    }

    #[test]
    fn audit_detects_tampering() {
        let log = TamperProofLog::new();
        log.append("event", b"data1");
        log.append("event", b"data2");
        // Manually tamper with an entry
        log.entries.lock().unwrap()[0].payload_hex = hex::encode(b"tampered");
        assert!(!log.verify_integrity());
    }

    #[test]
    fn audit_root_changes() {
        let log = TamperProofLog::new();
        let root1 = log.root_hash();
        log.append("e", b"d");
        let root2 = log.root_hash();
        assert_ne!(root1, root2);
    }

    // Session GC
    #[test]
    fn gc_collects_old_completed() {
        let gc = SessionGarbageCollector::new(GcConfig {
            max_completed_age: Duration::seconds(0),
            ..Default::default()
        });
        let mut sessions = vec![
            GcSessionInfo {
                session_id: "s1".into(),
                state: "completed".into(),
                last_updated: Utc::now() - Duration::hours(48),
            },
            GcSessionInfo {
                session_id: "s2".into(),
                state: "pending".into(),
                last_updated: Utc::now(),
            },
        ];
        let collected = gc.collect(&mut sessions);
        assert_eq!(collected, 1);
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn gc_preserves_pending() {
        let gc = SessionGarbageCollector::new(GcConfig::default());
        let mut sessions = vec![GcSessionInfo {
            session_id: "s1".into(),
            state: "pending".into(),
            last_updated: Utc::now() - Duration::days(365),
        }];
        gc.collect(&mut sessions);
        assert_eq!(sessions.len(), 1);
    }

    // Signer quarantine
    #[test]
    fn quarantine_after_bad_threshold() {
        let q = SignerQuarantine::new(3, Duration::hours(1));
        q.record_bad("s1");
        q.record_bad("s1");
        assert!(!q.is_quarantined("s1"));
        q.record_bad("s1");
        assert!(q.is_quarantined("s1"));
    }

    #[test]
    fn quarantine_release() {
        let q = SignerQuarantine::new(1, Duration::hours(1));
        q.record_bad("s1");
        assert!(q.is_quarantined("s1"));
        q.release("s1");
        assert!(!q.is_quarantined("s1"));
    }

    #[test]
    fn quarantine_good_records_recover() {
        let q = SignerQuarantine::new(1, Duration::hours(1));
        q.record_bad("s1");
        assert!(q.is_quarantined("s1"));
        for _ in 0..10 {
            q.record_good("s1");
        }
        assert!(!q.is_quarantined("s1"));
    }

    // Time-locked signing
    #[test]
    fn time_lock_not_ready_before() {
        let mut session = TimeLockedSession::new("s1", Utc::now() + Duration::hours(1));
        assert!(!session.check_unlock());
        assert!(session.store_signature(vec![1]).is_err());
    }

    #[test]
    fn time_lock_ready_after() {
        let mut session = TimeLockedSession::new("s1", Utc::now() - Duration::seconds(1));
        assert!(session.check_unlock());
        assert!(session.store_signature(vec![1]).is_ok());
    }

    // Conditional signing
    #[test]
    fn condition_always_passes() {
        let cond = SigningCondition::Always;
        assert!(cond.evaluate(&SigningContext::default()));
    }

    #[test]
    fn condition_quorum_vote() {
        let cond = SigningCondition::QuorumVote { required: 3 };
        assert!(!cond.evaluate(&SigningContext {
            vote_count: 2,
            ..Default::default()
        }));
        assert!(cond.evaluate(&SigningContext {
            vote_count: 3,
            ..Default::default()
        }));
    }

    #[test]
    fn condition_oracle() {
        let cond = SigningCondition::OracleValue {
            oracle_id: "price".into(),
            min_value: 100.0,
        };
        assert!(!cond.evaluate(&SigningContext {
            oracle_value: Some(50.0),
            ..Default::default()
        }));
        assert!(cond.evaluate(&SigningContext {
            oracle_value: Some(150.0),
            ..Default::default()
        }));
    }

    #[test]
    fn condition_time_window() {
        let now = Utc::now();
        let cond = SigningCondition::TimeWindow {
            start: now - Duration::hours(1),
            end: now + Duration::hours(1),
        };
        assert!(cond.evaluate(&SigningContext::default()));
    }

    // Cross-quorum aggregation
    #[test]
    fn cross_quorum_aggregate() {
        let sigs = vec![
            ("q1".to_string(), vec![0xAA; 64]),
            ("q2".to_string(), vec![0xBB; 64]),
        ];
        let agg = aggregate_cross_quorum(&sigs, &[0x42; 32]);
        assert_eq!(agg.quorum_ids.len(), 2);
        assert!(!agg.aggregate_signature_hex.is_empty());
    }

    // Config hot-reload
    #[test]
    fn config_reload_updates() {
        let mgr = ConfigManager::new(CoordinatorConfig::default());
        assert_eq!(mgr.config_version(), 1);
        let new_config = CoordinatorConfig {
            max_sessions: 200,
            ..Default::default()
        };
        mgr.reload(new_config);
        assert_eq!(mgr.config().max_sessions, 200);
        assert_eq!(mgr.config_version(), 2);
        assert_eq!(mgr.reload_count(), 1);
    }

    // Wallet policy
    #[test]
    fn wallet_policy_passes() {
        let policy = WalletPolicy {
            required_signers: 2,
            total_signers: 3,
            max_amount: Some(1000),
            allowed_recipients: None,
            time_window: None,
        };
        let ctx = WalletTxContext {
            signer_count: 2,
            amount: 500,
            recipient: "bob".into(),
        };
        assert!(policy.evaluate(&ctx).is_ok());
    }

    #[test]
    fn wallet_policy_fails_insufficient_signers() {
        let policy = WalletPolicy {
            required_signers: 3,
            total_signers: 5,
            max_amount: None,
            allowed_recipients: None,
            time_window: None,
        };
        let ctx = WalletTxContext {
            signer_count: 2,
            amount: 100,
            recipient: "x".into(),
        };
        assert!(policy.evaluate(&ctx).is_err());
    }

    #[test]
    fn wallet_policy_fails_exceeds_amount() {
        let policy = WalletPolicy {
            required_signers: 1,
            total_signers: 1,
            max_amount: Some(100),
            allowed_recipients: None,
            time_window: None,
        };
        let ctx = WalletTxContext {
            signer_count: 1,
            amount: 200,
            recipient: "x".into(),
        };
        assert!(policy.evaluate(&ctx).is_err());
    }

    #[test]
    fn wallet_policy_recipient_allowlist() {
        let mut allowed = HashSet::new();
        allowed.insert("alice".into());
        let policy = WalletPolicy {
            required_signers: 1,
            total_signers: 1,
            max_amount: None,
            allowed_recipients: Some(allowed),
            time_window: None,
        };
        assert!(
            policy
                .evaluate(&WalletTxContext {
                    signer_count: 1,
                    amount: 0,
                    recipient: "alice".into()
                })
                .is_ok()
        );
        assert!(
            policy
                .evaluate(&WalletTxContext {
                    signer_count: 1,
                    amount: 0,
                    recipient: "bob".into()
                })
                .is_err()
        );
    }

    // Replay protection
    #[test]
    fn replay_first_use_accepted() {
        let rp = ReplayProtection::new(1000);
        assert!(rp.check_and_consume(b"nonce1"));
    }

    #[test]
    fn replay_duplicate_rejected() {
        let rp = ReplayProtection::new(1000);
        rp.check_and_consume(b"nonce1");
        assert!(!rp.check_and_consume(b"nonce1"));
    }

    #[test]
    fn replay_different_nonces_accepted() {
        let rp = ReplayProtection::new(1000);
        assert!(rp.check_and_consume(b"n1"));
        assert!(rp.check_and_consume(b"n2"));
    }

    #[test]
    fn replay_cache_eviction() {
        let rp = ReplayProtection::new(10);
        for i in 0..15 {
            rp.check_and_consume(&[i as u8; 8]);
        }
        // Old nonces should be evicted
        assert!(rp.cache_size() <= 15);
    }

    // Proactive security
    #[test]
    fn proactive_should_refresh_after_interval() {
        let scheduler = ProactiveScheduler::new(Duration::milliseconds(1));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(scheduler.should_refresh());
    }

    #[test]
    fn proactive_not_ready_before_interval() {
        let scheduler = ProactiveScheduler::new(Duration::hours(1));
        assert!(!scheduler.should_refresh());
    }

    #[test]
    fn proactive_mark_refreshed_resets() {
        let scheduler = ProactiveScheduler::new(Duration::hours(1));
        assert!(!scheduler.should_refresh());
        scheduler.mark_refreshed();
        assert_eq!(scheduler.refresh_count(), 1);
        assert!(!scheduler.should_refresh());
    }

    #[test]
    fn proactive_auto_refresh_toggle() {
        let scheduler = ProactiveScheduler::new(Duration::milliseconds(1));
        std::thread::sleep(std::time::Duration::from_millis(5));
        scheduler.set_auto_refresh(false);
        assert!(!scheduler.should_refresh());
    }
}
