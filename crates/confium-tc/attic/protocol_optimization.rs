//! Protocol optimization + operational intelligence.
//!
//! Binary encoding, known-answer tests, batch DKG, adaptive rate limiting,
//! priority sessions, health scoring, key rotation scheduling,
//! content-addressed cache, SSE streaming, audit compression.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

// === Binary Protocol Encoding ===

pub struct BinaryEncoder { buf: Vec<u8> }

impl BinaryEncoder {
    pub fn new() -> Self { Self { buf: Vec::new() } }

    pub fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        self.write_u32(data.len() as u32);
        self.buf.extend_from_slice(data);
    }

    pub fn write_string(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    pub fn finish(self) -> Vec<u8> { self.buf }
}

pub struct BinaryDecoder<'a> { buf: &'a [u8], pos: usize }

impl<'a> BinaryDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }

    pub fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.buf.len() { return None; }
        let val = u32::from_be_bytes(self.buf[self.pos..self.pos+4].try_into().ok()?);
        self.pos += 4;
        Some(val)
    }

    pub fn read_bytes(&mut self) -> Option<Vec<u8>> {
        let len = self.read_u32()? as usize;
        if self.pos + len > self.buf.len() { return None; }
        let data = self.buf[self.pos..self.pos+len].to_vec();
        self.pos += len;
        Some(data)
    }

    pub fn read_string(&mut self) -> Option<String> {
        String::from_utf8(self.read_bytes()?).ok()
    }

    pub fn remaining(&self) -> usize { self.buf.len().saturating_sub(self.pos) }
}

// === Known-Answer Test Framework ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownAnswerTest {
    pub name: String,
    pub input_hex: String,
    pub expected_output_hex: String,
    pub description: String,
}

pub struct KatRunner { tests: Vec<KnownAnswerTest>, results: Vec<KatResult> }

#[derive(Debug, Clone)]
pub struct KatResult { pub name: String, pub passed: bool, pub actual_hex: String }

impl KatRunner {
    pub fn new(tests: Vec<KnownAnswerTest>) -> Self { Self { tests, results: Vec::new() } }

    pub fn run<F>(&mut self, compute: F) -> &mut Self
    where F: Fn(&[u8]) -> Vec<u8> {
        self.results = self.tests.iter().map(|t| {
            let input = hex::decode(&t.input_hex).unwrap_or_default();
            let output = compute(&input);
            let passed = hex::encode(&output) == t.expected_output_hex;
            KatResult { name: t.name.clone(), passed, actual_hex: hex::encode(&output) }
        }).collect();
        self
    }

    pub fn pass_count(&self) -> usize { self.results.iter().filter(|r| r.passed).count() }
    pub fn fail_count(&self) -> usize { self.results.iter().filter(|r| !r.passed).count() }
    pub fn all_passed(&self) -> bool { self.fail_count() == 0 }
    pub fn results(&self) -> &[KatResult] { &self.results }
}

// === Batch DKG ===

#[derive(Debug, Clone)]
pub struct BatchDkgResult {
    pub keyset_ids: Vec<String>,
    pub public_keys_hex: Vec<String>,
}

pub struct BatchDkg {
    batch_size: usize,
    completed: Mutex<Vec<String>>,
}

impl BatchDkg {
    pub fn new(batch_size: usize) -> Self { Self { batch_size, completed: Mutex::new(Vec::new()) } }

    pub fn generate_batch(&self, prefix: &str) -> BatchDkgResult {
        let keyset_ids: Vec<String> = (0..self.batch_size)
            .map(|i| format!("{prefix}-ks{i}")).collect();
        let public_keys_hex: Vec<String> = keyset_ids.iter()
            .map(|id| {
                let mut h = Sha256::new();
                h.update(id.as_bytes());
                hex::encode(h.finalize())
            })
            .collect();
        self.completed.lock().unwrap().extend(keyset_ids.clone());
        BatchDkgResult { keyset_ids, public_keys_hex }
    }

    pub fn completed_count(&self) -> usize { self.completed.lock().unwrap().len() }
    pub fn batch_size(&self) -> usize { self.batch_size }
}

// === Adaptive Rate Limiting (AIMD) ===

pub struct AdaptiveRateLimiter {
    limit: AtomicU32,
    min_limit: u32,
    max_limit: u32,
    additive_increase: u32,
    multiplicative_decrease: f64,
    window: Mutex<Vec<bool>>, // true = success, false = failure
    window_size: usize,
}

impl AdaptiveRateLimiter {
    pub fn new(initial: u32, min: u32, max: u32) -> Self {
        Self {
            limit: AtomicU32::new(initial), min_limit: min, max_limit: max,
            additive_increase: 1, multiplicative_decrease: 0.5,
            window: Mutex::new(Vec::new()), window_size: 100,
        }
    }

    pub fn current_limit(&self) -> u32 { self.limit.load(Ordering::SeqCst) }

    pub fn record_success(&self) {
        let mut window = self.window.lock().unwrap();
        window.push(true);
        if window.len() >= self.window_size {
            let failures = window.iter().filter(|&&s| !s).count();
            let rate = failures as f64 / self.window_size as f64;
            if rate < 0.01 {
                // Low error rate: increase limit
                let new = (self.limit.load(Ordering::SeqCst) + self.additive_increase).min(self.max_limit);
                self.limit.store(new, Ordering::SeqCst);
            }
            window.clear();
        }
    }

    pub fn record_failure(&self) {
        let mut window = self.window.lock().unwrap();
        window.push(false);
        if window.len() >= self.window_size {
            let failures = window.iter().filter(|&&s| !s).count();
            let rate = failures as f64 / self.window_size as f64;
            if rate > 0.05 {
                // High error rate: decrease limit
                let current = self.limit.load(Ordering::SeqCst);
                let new = ((current as f64 * self.multiplicative_decrease) as u32).max(self.min_limit);
                self.limit.store(new, Ordering::SeqCst);
            }
            window.clear();
        }
    }
}

// === Priority Session Queue ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritySession {
    pub session_id: String,
    pub priority: u8, // 0 = highest
    pub created_at: DateTime<Utc>,
}

pub struct PrioritySessionQueue {
    queue: Mutex<BTreeMap<(u8, DateTime<Utc>), PrioritySession>>,
}

impl PrioritySessionQueue {
    pub fn new() -> Self { Self { queue: Mutex::new(BTreeMap::new()) } }

    pub fn enqueue(&self, session: PrioritySession) {
        let key = (session.priority, session.created_at);
        self.queue.lock().unwrap().insert(key, session);
    }

    pub fn dequeue(&self) -> Option<PrioritySession> {
        let mut queue = self.queue.lock().unwrap();
        let key = queue.keys().next().copied()?;
        queue.remove(&key)
    }

    pub fn peek_priority(&self) -> Option<u8> {
        self.queue.lock().unwrap().keys().next().map(|k| k.0)
    }

    pub fn len(&self) -> usize { self.queue.lock().unwrap().len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl Default for PrioritySessionQueue { fn default() -> Self { Self::new() } }

// === Coordinator Health Scoring ===

#[derive(Debug, Clone)]
pub struct HealthMetrics {
    pub error_rate: f64,
    pub avg_latency_ms: f64,
    pub capacity_used: f64, // 0.0-1.0
    pub staleness_secs: u64,
}

pub struct HealthScorer;

impl HealthScorer {
    pub fn score(m: &HealthMetrics) -> u32 {
        let mut score = 100u32;
        // Error rate penalty
        if m.error_rate > 0.01 { score -= (m.error_rate * 100.0) as u32 * 2; }
        // Latency penalty (>500ms starts reducing)
        if m.avg_latency_ms > 500.0 { score -= ((m.avg_latency_ms - 500.0) / 50.0) as u32; }
        // Capacity penalty (>80% starts reducing)
        if m.capacity_used > 0.8 { score -= ((m.capacity_used - 0.8) * 100.0) as u32 * 2; }
        // Staleness penalty (>60s starts reducing)
        if m.staleness_secs > 60 { score -= ((m.staleness_secs - 60) / 10) as u32; }
        score.min(100)
    }

    pub fn grade(score: u32) -> char {
        match score {
            90..=100 => 'A',
            80..=89 => 'B',
            70..=79 => 'C',
            60..=69 => 'D',
            _ => 'F',
        }
    }
}

// === Scheduled Key Rotation ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPlan {
    pub key_id: String,
    pub interval_days: u32,
    pub next_rotation: DateTime<Utc>,
    pub rotations_completed: u32,
}

pub struct RotationScheduler {
    plans: Mutex<HashMap<String, RotationPlan>>,
    rotation_log: Mutex<Vec<(String, DateTime<Utc>)>>,
}

impl RotationScheduler {
    pub fn new() -> Self { Self { plans: Mutex::new(HashMap::new()), rotation_log: Mutex::new(Vec::new()) } }

    pub fn schedule(&self, key_id: &str, interval_days: u32) {
        self.plans.lock().unwrap().insert(key_id.into(), RotationPlan {
            key_id: key_id.into(), interval_days,
            next_rotation: Utc::now() + Duration::days(interval_days as i64),
            rotations_completed: 0,
        });
    }

    pub fn check_and_rotate(&self) -> Vec<String> {
        let now = Utc::now();
        let mut plans = self.plans.lock().unwrap();
        let mut rotated = Vec::new();
        for plan in plans.values_mut() {
            if now >= plan.next_rotation {
                plan.rotations_completed += 1;
                plan.next_rotation = now + Duration::days(plan.interval_days as i64);
                rotated.push(plan.key_id.clone());
                self.rotation_log.lock().unwrap().push((plan.key_id.clone(), now));
            }
        }
        rotated
    }

    pub fn next_rotation(&self, key_id: &str) -> Option<DateTime<Utc>> {
        self.plans.lock().unwrap().get(key_id).map(|p| p.next_rotation)
    }

    pub fn rotation_count(&self, key_id: &str) -> Option<u32> {
        self.plans.lock().unwrap().get(key_id).map(|p| p.rotations_completed)
    }

    pub fn total_rotations(&self) -> usize { self.rotation_log.lock().unwrap().len() }
    pub fn scheduled_count(&self) -> usize { self.plans.lock().unwrap().len() }
}

impl Default for RotationScheduler { fn default() -> Self { Self::new() } }

// === Content-Addressed Signature Cache ===

pub struct ContentAddressedCache {
    entries: Mutex<HashMap<String, Vec<u8>>>,
    hits: AtomicU64,
    misses: AtomicU64,
    max_entries: usize,
}

impl ContentAddressedCache {
    pub fn new(max_entries: usize) -> Self {
        Self { entries: Mutex::new(HashMap::new()), hits: AtomicU64::new(0),
               misses: AtomicU64::new(0), max_entries }
    }

    fn content_hash(key: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(key);
        hex::encode(h.finalize())
    }

    pub fn store(&self, key: &[u8], value: Vec<u8>) {
        let hash = Self::content_hash(key);
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.max_entries {
            // Evict oldest (simplified: remove first)
            if let Some(first_key) = entries.keys().next().cloned() {
                entries.remove(&first_key);
            }
        }
        entries.insert(hash, value);
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let hash = Self::content_hash(key);
        let result = self.entries.lock().unwrap().get(&hash).cloned();
        if result.is_some() { self.hits.fetch_add(1, Ordering::SeqCst); }
        else { self.misses.fetch_add(1, Ordering::SeqCst); }
        result
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::SeqCst);
        let misses = self.misses.load(Ordering::SeqCst);
        let total = hits + misses;
        if total == 0 { 0.0 } else { hits as f64 / total as f64 }
    }

    pub fn entry_count(&self) -> usize { self.entries.lock().unwrap().len() }
    pub fn hits(&self) -> u64 { self.hits.load(Ordering::SeqCst) }
    pub fn misses(&self) -> u64 { self.misses.load(Ordering::SeqCst) }
}

// === Session Result Streaming (SSE) ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseEvent {
    pub event_type: String,
    pub data: String,
    pub id: u64,
    pub timestamp: DateTime<Utc>,
}

pub struct SseStream {
    events: Mutex<VecDeque<SseEvent>>,
    subscribers: Mutex<Vec<SseSubscriber>>,
    next_id: AtomicU64,
}

struct SseSubscriber {
    last_event_id: u64,
    filters: Vec<String>,
}

impl SseStream {
    pub fn new() -> Self {
        Self { events: Mutex::new(VecDeque::new()), subscribers: Mutex::new(Vec::new()),
               next_id: AtomicU64::new(1) }
    }

    pub fn publish(&self, event_type: &str, data: &str) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.events.lock().unwrap().push_back(SseEvent {
            event_type: event_type.into(), data: data.into(), id, timestamp: Utc::now(),
        });
        id
    }

    pub fn subscribe(&self, filters: Vec<String>) -> usize {
        let last_id = self.events.lock().unwrap().back().map(|e| e.id).unwrap_or(0);
        self.subscribers.lock().unwrap().push(SseSubscriber { last_event_id: last_id, filters });
        self.subscribers.lock().unwrap().len() - 1
    }

    pub fn poll(&self, subscriber_id: usize) -> Vec<SseEvent> {
        let subs = self.subscribers.lock().unwrap();
        let sub = match subs.get(subscriber_id) { Some(s) => s, None => return Vec::new() };
        let events = self.events.lock().unwrap();
        events.iter()
            .filter(|e| e.id > sub.last_event_id)
            .filter(|e| sub.filters.is_empty() || sub.filters.iter().any(|f| f == &e.event_type))
            .cloned()
            .collect()
    }

    pub fn format_sse(event: &SseEvent) -> String {
        format!("id: {}\nevent: {}\ndata: {}\n\n", event.id, event.event_type, event.data)
    }

    pub fn event_count(&self) -> usize { self.events.lock().unwrap().len() }
    pub fn subscriber_count(&self) -> usize { self.subscribers.lock().unwrap().len() }
}

impl Default for SseStream { fn default() -> Self { Self::new() } }

// === Audit Log Compression and Archival ===

pub struct AuditArchiver {
    config: ArchiveConfig,
    archived: AtomicU64,
    compressed_bytes: AtomicU64,
    original_bytes: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    pub max_entries_before_archive: usize,
    pub compression_threshold_bytes: usize,
}

impl Default for ArchiveConfig {
    fn default() -> Self { Self { max_entries_before_archive: 10_000, compression_threshold_bytes: 1024 } }
}

impl AuditArchiver {
    pub fn new(config: ArchiveConfig) -> Self {
        Self { config, archived: AtomicU64::new(0),
               compressed_bytes: AtomicU64::new(0), original_bytes: AtomicU64::new(0) }
    }

    pub fn should_archive(&self, entry_count: usize) -> bool {
        entry_count >= self.config.max_entries_before_archive
    }

    pub fn archive(&self, entries: &[String]) -> Vec<u8> {
        let original: Vec<u8> = entries.join("\n").into_bytes();
        let original_size = original.len();
        // Simple "compression": remove repeated whitespace + dictionary encoding (mock)
        let compressed = self.simple_compress(&original);
        self.archived.fetch_add(entries.len() as u64, Ordering::SeqCst);
        self.original_bytes.fetch_add(original_size as u64, Ordering::SeqCst);
        self.compressed_bytes.fetch_add(compressed.len() as u64, Ordering::SeqCst);
        compressed
    }

    fn simple_compress(&self, data: &[u8]) -> Vec<u8> {
        let mut compressed = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let byte = data[i];
            let mut count: u8 = 1;
            loop {
                if count >= 255 { break; }
                let next_idx = i + (count as usize);
                if next_idx >= data.len() { break; }
                if data[next_idx] != byte { break; }
                count += 1;
            }
            compressed.push(byte);
            if count > 3 { compressed.push(count); }
            i += count as usize;
        }
        compressed
    }

    pub fn compression_ratio(&self) -> f64 {
        let original = self.original_bytes.load(Ordering::SeqCst);
        let compressed = self.compressed_bytes.load(Ordering::SeqCst);
        if original == 0 { return 1.0; }
        compressed as f64 / original as f64
    }

    pub fn total_archived(&self) -> u64 { self.archived.load(Ordering::SeqCst) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Binary encoding
    #[test]
    fn binary_round_trip() {
        let mut enc = BinaryEncoder::new();
        enc.write_string("hello");
        enc.write_u32(42);
        enc.write_bytes(&[1, 2, 3]);
        let encoded = enc.finish();
        let mut dec = BinaryDecoder::new(&encoded);
        assert_eq!(dec.read_string(), Some("hello".into()));
        assert_eq!(dec.read_u32(), Some(42));
        assert_eq!(dec.read_bytes(), Some(vec![1, 2, 3]));
    }

    #[test]
    fn binary_empty_string() {
        let mut enc = BinaryEncoder::new();
        enc.write_string("");
        let encoded = enc.finish();
        let mut dec = BinaryDecoder::new(&encoded);
        assert_eq!(dec.read_string(), Some("".into()));
    }

    // Known-answer tests
    #[test]
    fn kat_all_pass() {
        let tests = vec![
            KnownAnswerTest { name: "t1".into(), input_hex: "0102".into(), expected_output_hex: hex::encode(&[3]), description: "sum".into() },
            KnownAnswerTest { name: "t2".into(), input_hex: "0304".into(), expected_output_hex: hex::encode(&[7]), description: "sum".into() },
        ];
        let mut runner = KatRunner::new(tests);
        runner.run(|input| vec![input.iter().sum()]);
        assert!(runner.all_passed());
        assert_eq!(runner.pass_count(), 2);
    }

    #[test]
    fn kat_detects_failure() {
        let tests = vec![
            KnownAnswerTest { name: "t1".into(), input_hex: "01".into(), expected_output_hex: "ff".into(), description: "should fail".into() },
        ];
        let mut runner = KatRunner::new(tests);
        runner.run(|input| vec![input.iter().sum()]);
        assert!(!runner.all_passed());
        assert_eq!(runner.fail_count(), 1);
    }

    // Batch DKG
    #[test]
    fn batch_dkg_generates() {
        let dkg = BatchDkg::new(5);
        let result = dkg.generate_batch("quorum-1");
        assert_eq!(result.keyset_ids.len(), 5);
        assert_eq!(result.public_keys_hex.len(), 5);
        assert_eq!(dkg.completed_count(), 5);
    }

    // Adaptive rate limiting
    #[test]
    fn adaptive_increases_on_success() {
        let limiter = AdaptiveRateLimiter::new(10, 1, 100);
        for _ in 0..100 { limiter.record_success(); }
        assert!(limiter.current_limit() > 10);
    }

    #[test]
    fn adaptive_decreases_on_failure() {
        let limiter = AdaptiveRateLimiter::new(50, 1, 100);
        for _ in 0..100 { limiter.record_failure(); }
        assert!(limiter.current_limit() < 50);
    }

    // Priority queue
    #[test]
    fn priority_queue_orders_by_priority() {
        let q = PrioritySessionQueue::new();
        q.enqueue(PrioritySession { session_id: "low".into(), priority: 5, created_at: Utc::now() });
        q.enqueue(PrioritySession { session_id: "high".into(), priority: 1, created_at: Utc::now() });
        let first = q.dequeue().unwrap();
        assert_eq!(first.session_id, "high");
    }

    #[test]
    fn priority_queue_empty() {
        let q = PrioritySessionQueue::new();
        assert!(q.is_empty());
        assert!(q.dequeue().is_none());
    }

    // Health scoring
    #[test]
    fn health_perfect_score() {
        let m = HealthMetrics { error_rate: 0.0, avg_latency_ms: 10.0, capacity_used: 0.1, staleness_secs: 0 };
        assert_eq!(HealthScorer::score(&m), 100);
        assert_eq!(HealthScorer::grade(100), 'A');
    }

    #[test]
    fn health_degraded_by_errors() {
        let m = HealthMetrics { error_rate: 0.5, avg_latency_ms: 10.0, capacity_used: 0.1, staleness_secs: 0 };
        let score = HealthScorer::score(&m);
        assert!(score < 100);
    }

    #[test]
    fn health_degraded_by_capacity() {
        let m = HealthMetrics { error_rate: 0.0, avg_latency_ms: 10.0, capacity_used: 0.95, staleness_secs: 0 };
        let score = HealthScorer::score(&m);
        assert!(score < 100);
    }

    // Key rotation
    #[test]
    fn rotation_scheduled() {
        let sched = RotationScheduler::new();
        sched.schedule("key-1", 30);
        assert_eq!(sched.scheduled_count(), 1);
        assert!(sched.next_rotation("key-1").is_some());
    }

    #[test]
    fn rotation_check_past_due() {
        let sched = RotationScheduler::new();
        {
            let mut plans = sched.plans.lock().unwrap();
            plans.insert("key-1".into(), RotationPlan {
                key_id: "key-1".into(), interval_days: 30,
                next_rotation: Utc::now() - Duration::days(1),
                rotations_completed: 0,
            });
        }
        let rotated = sched.check_and_rotate();
        assert_eq!(rotated, vec!["key-1"]);
        assert_eq!(sched.rotation_count("key-1"), Some(1));
    }

    // Content-addressed cache
    #[test]
    fn cache_store_and_get() {
        let cache = ContentAddressedCache::new(100);
        cache.store(b"key1", vec![0xAA; 32]);
        assert_eq!(cache.get(b"key1"), Some(vec![0xAA; 32]));
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn cache_miss_tracked() {
        let cache = ContentAddressedCache::new(100);
        assert!(cache.get(b"missing").is_none());
        assert_eq!(cache.misses(), 1);
        assert_eq!(cache.hit_rate(), 0.0);
    }

    #[test]
    fn cache_deduplicates() {
        let cache = ContentAddressedCache::new(100);
        cache.store(b"key1", vec![1]);
        cache.store(b"key1", vec![2]); // overwrite
        assert_eq!(cache.entry_count(), 1);
    }

    // SSE streaming
    #[test]
    fn sse_publish_and_poll() {
        let stream = SseStream::new();
        let sub = stream.subscribe(vec![]);
        stream.publish("created", "session-1");
        stream.publish("signed", "session-1");
        let events = stream.poll(sub);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn sse_filtered_subscription() {
        let stream = SseStream::new();
        let sub = stream.subscribe(vec!["signed".into()]);
        stream.publish("created", "s1");
        stream.publish("signed", "s1");
        let events = stream.poll(sub);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "signed");
    }

    #[test]
    fn sse_format() {
        let event = SseEvent { event_type: "test".into(), data: "hello".into(), id: 1, timestamp: Utc::now() };
        let formatted = SseStream::format_sse(&event);
        assert!(formatted.contains("id: 1"));
        assert!(formatted.contains("event: test"));
        assert!(formatted.contains("data: hello"));
    }

    // Audit compression
    #[test]
    fn audit_compress_reduces_size() {
        let archiver = AuditArchiver::new(ArchiveConfig { max_entries_before_archive: 1, compression_threshold_bytes: 0 });
        let entries = vec!["AAAA".repeat(100); 10];
        let compressed = archiver.archive(&entries);
        // RLE should compress repeated 'A's
        assert!(compressed.len() < entries.join("\n").len());
        assert!(archiver.compression_ratio() < 1.0);
    }

    #[test]
    fn audit_should_archive() {
        let archiver = AuditArchiver::new(ArchiveConfig { max_entries_before_archive: 5, compression_threshold_bytes: 0 });
        assert!(!archiver.should_archive(3));
        assert!(archiver.should_archive(5));
    }
}
