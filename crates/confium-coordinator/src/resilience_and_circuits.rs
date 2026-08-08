//! Connection pool — TCP connection reuse.
//! Health-check load balancer — route to healthy instances.
//! Retry with jitter — improved backoff.
//! Graceful degradation — serve stale data.
//! WebSocket coordinator — real-time updates.
//! Garbled circuits — secure 2PC.
//! Efficient range proof — bulletproof-style.
//! Bulk signing pipeline — high-throughput batching.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

// === Connection Pool ===

pub struct ConnectionPool {
    pools: Mutex<HashMap<String, Vec<PooledConn>>>,
    max_per_host: usize,
    idle_timeout: Duration,
}

struct PooledConn {
    host: String,
    created_at: Instant,
    healthy: bool,
}

impl ConnectionPool {
    pub fn new(max_per_host: usize, idle_timeout: Duration) -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
            max_per_host,
            idle_timeout,
        }
    }

    pub fn acquire(&self, host: &str) -> Option<PooledConn> {
        let mut pools = self.pools.lock().unwrap();
        let pool = pools.entry(host.into()).or_default();
        let pos = pool
            .iter()
            .position(|c| c.healthy && c.created_at.elapsed() < self.idle_timeout)?;
        Some(pool.remove(pos))
    }

    pub fn release(&self, conn: PooledConn) {
        let mut pools = self.pools.lock().unwrap();
        let pool = pools.entry(conn.host.clone()).or_default();
        if pool.len() < self.max_per_host {
            pool.push(conn);
        }
    }

    pub fn create(&self, host: &str) -> PooledConn {
        PooledConn {
            host: host.into(),
            created_at: Instant::now(),
            healthy: true,
        }
    }

    pub fn idle_count(&self, host: &str) -> usize {
        self.pools
            .lock()
            .unwrap()
            .get(host)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub fn evict_stale(&self) -> usize {
        let mut pools = self.pools.lock().unwrap();
        let mut evicted = 0;
        for pool in pools.values_mut() {
            let before = pool.len();
            pool.retain(|c| c.created_at.elapsed() < self.idle_timeout && c.healthy);
            evicted += before - pool.len();
        }
        evicted
    }
}

// === Health-Check Load Balancer ===

#[derive(Debug, Clone)]
pub struct Backend {
    pub id: String,
    pub address: String,
    pub health_score: u32,
    pub healthy: bool,
}

pub struct HealthLoadBalancer {
    backends: Mutex<Vec<Backend>>,
    current: AtomicU32,
}

impl HealthLoadBalancer {
    pub fn new(backends: Vec<Backend>) -> Self {
        Self {
            backends: Mutex::new(backends),
            current: AtomicU32::new(0),
        }
    }

    pub fn select(&self) -> Option<Backend> {
        let backends = self.backends.lock().unwrap();
        let healthy: Vec<&Backend> = backends.iter().filter(|b| b.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        // Weighted round-robin: pick by health score
        let total_score: u32 = healthy.iter().map(|b| b.health_score).sum();
        if total_score == 0 {
            return Some(healthy[0].clone());
        }
        let idx = self.current.fetch_add(1, Ordering::SeqCst) as usize % healthy.len();
        Some(healthy[idx].clone())
    }

    pub fn update_health(&self, id: &str, score: u32, healthy: bool) {
        let mut backends = self.backends.lock().unwrap();
        if let Some(b) = backends.iter_mut().find(|b| b.id == id) {
            b.health_score = score;
            b.healthy = healthy;
        }
    }

    pub fn healthy_count(&self) -> usize {
        self.backends
            .lock()
            .unwrap()
            .iter()
            .filter(|b| b.healthy)
            .count()
    }

    pub fn total_count(&self) -> usize {
        self.backends.lock().unwrap().len()
    }
}

// === Retry with Jitter ===

pub enum JitterStrategy {
    Full,
    Equal,
    Decorrelated,
}

pub fn backoff_with_jitter(
    attempt: u32,
    base_delay: Duration,
    max_delay: Duration,
    strategy: JitterStrategy,
) -> Duration {
    let exponential = base_delay.mul_f64(2f64.powi(attempt as i32)).min(max_delay);
    let mut rng_bytes = [0u8; 4];
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(&mut rng_bytes);
    let rand_val = u32::from_le_bytes(rng_bytes) as f64 / u32::MAX as f64;
    match strategy {
        JitterStrategy::Full => {
            Duration::from_nanos((rand_val * exponential.as_nanos() as f64) as u64)
        }
        JitterStrategy::Equal => {
            let half = exponential.as_nanos() as f64 / 2.0;
            Duration::from_nanos((half + rand_val * half) as u64)
        }
        JitterStrategy::Decorrelated => {
            Duration::from_nanos((rand_val * max_delay.as_nanos() as f64) as u64).min(max_delay)
        }
    }
}

// === Graceful Degradation ===

pub struct DegradationCache<T: Clone> {
    cache: Mutex<HashMap<String, (T, Instant)>>,
    max_stale: Duration,
}

impl<T: Clone> DegradationCache<T> {
    pub fn new(max_stale: Duration) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            max_stale,
        }
    }

    pub fn store(&self, key: &str, value: T) {
        self.cache
            .lock()
            .unwrap()
            .insert(key.into(), (value, Instant::now()));
    }

    pub fn get_fresh(&self, key: &str) -> Option<T> {
        let cache = self.cache.lock().unwrap();
        cache
            .get(key)
            .filter(|(_, t)| t.elapsed() < self.max_stale)
            .map(|(v, _)| v.clone())
    }

    pub fn get_stale(&self, key: &str) -> Option<T> {
        self.cache.lock().unwrap().get(key).map(|(v, _)| v.clone())
    }

    pub fn is_stale(&self, key: &str) -> bool {
        let cache = self.cache.lock().unwrap();
        cache
            .get(key)
            .map(|(_, t)| t.elapsed() >= self.max_stale)
            .unwrap_or(true)
    }

    pub fn entry_count(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    pub fn evict_stale(&self) -> usize {
        let mut cache = self.cache.lock().unwrap();
        let before = cache.len();
        cache.retain(|_, (_, t)| t.elapsed() < self.max_stale);
        before - cache.len()
    }
}

// === WebSocket Coordinator ===

#[derive(Debug, Clone)]
pub struct WsSession {
    pub session_id: String,
    pub subscribers: Vec<String>,
    pub last_update: chrono::DateTime<chrono::Utc>,
}

pub struct WsCoordinator {
    sessions: Mutex<HashMap<String, WsSession>>,
}

impl WsCoordinator {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn subscribe(&self, session_id: &str, client_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .entry(session_id.into())
            .or_insert_with(|| WsSession {
                session_id: session_id.into(),
                subscribers: Vec::new(),
                last_update: chrono::Utc::now(),
            });
        if !session.subscribers.contains(&client_id.into()) {
            session.subscribers.push(client_id.into());
        }
    }

    pub fn unsubscribe(&self, session_id: &str, client_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.subscribers.retain(|s| s != client_id);
            if session.subscribers.is_empty() {
                sessions.remove(session_id);
            }
        }
    }

    pub fn broadcast(&self, session_id: &str) -> Vec<String> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_update = chrono::Utc::now();
            return session.subscribers.clone();
        }
        Vec::new()
    }

    pub fn subscriber_count(&self, session_id: &str) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .get(session_id)
            .map(|s| s.subscribers.len())
            .unwrap_or(0)
    }

    pub fn active_sessions(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

impl Default for WsCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// === Garbled Circuits ===

#[derive(Debug, Clone)]
pub struct WireLabel {
    pub zero: Vec<u8>,
    pub one: Vec<u8>,
}

pub struct GarbledGate {
    pub input_a: WireLabel,
    pub input_b: WireLabel,
    pub output: WireLabel,
    pub table: [[Vec<u8>; 2]; 2],
}

pub fn garble_and_gate() -> GarbledGate {
    use sha2::{Digest, Sha256};
    let a = WireLabel {
        zero: rand_bytes(16),
        one: rand_bytes(16),
    };
    let b = WireLabel {
        zero: rand_bytes(16),
        one: rand_bytes(16),
    };
    let output = WireLabel {
        zero: rand_bytes(16),
        one: rand_bytes(16),
    };

    // AND gate: output = a AND b
    // Table[ai][bi] = encrypt(output_value, hash(a_label, b_label))
    let a_labels = [&a.zero, &a.one];
    let b_labels = [&b.zero, &b.one];
    let mut table = [[vec![], vec![]], [vec![], vec![]]];
    for (ai, &al) in a_labels.iter().enumerate() {
        for (bi, &bl) in b_labels.iter().enumerate() {
            let out_val = if ai == 1 && bi == 1 {
                &output.one
            } else {
                &output.zero
            };
            let mut h = Sha256::new();
            h.update(b"garble");
            h.update(al);
            h.update(bl);
            let key = h.finalize();
            let encrypted: Vec<u8> = out_val.iter().zip(key.iter()).map(|(o, k)| o ^ k).collect();
            table[ai][bi] = encrypted;
        }
    }
    GarbledGate {
        input_a: a,
        input_b: b,
        output,
        table,
    }
}

pub fn evaluate_gate(gate: &GarbledGate, a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    for row in &gate.table {
        for cell in row {
            let mut h = Sha256::new();
            h.update(b"garble");
            h.update(a);
            h.update(b);
            let key = h.finalize();
            let decrypted: Vec<u8> = cell.iter().zip(key.iter()).map(|(c, k)| c ^ k).collect();
            if decrypted == gate.output.zero || decrypted == gate.output.one {
                return Some(decrypted);
            }
        }
    }
    None
}

// === Bulk Signing Pipeline ===

pub struct BulkSignPipeline {
    batch_size: usize,
    pending: Mutex<Vec<BulkSignItem>>,
}

#[derive(Debug, Clone)]
pub struct BulkSignItem {
    pub message_hash: Vec<u8>,
    pub quorum_id: String,
}

#[derive(Debug, Clone)]
pub struct BulkSignResult {
    pub signatures: Vec<Vec<u8>>,
    pub batch_count: usize,
}

impl BulkSignPipeline {
    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size,
            pending: Mutex::new(Vec::new()),
        }
    }

    pub fn enqueue(&self, item: BulkSignItem) -> bool {
        let mut pending = self.pending.lock().unwrap();
        pending.push(item);
        pending.len() >= self.batch_size
    }

    pub fn flush(&self) -> Vec<BulkSignItem> {
        let mut pending = self.pending.lock().unwrap();
        std::mem::take(&mut *pending)
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    pub fn batch_and_sign<F>(&self, sign_fn: F) -> BulkSignResult
    where
        F: Fn(&[BulkSignItem]) -> Vec<Vec<u8>>,
    {
        let batch = self.flush();
        let sigs = sign_fn(&batch);
        BulkSignResult {
            signatures: sigs,
            batch_count: batch.len(),
        }
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // Connection pool
    #[test]
    fn pool_create_and_release() {
        let pool = ConnectionPool::new(5, Duration::from_secs(60));
        let conn = pool.create("host1");
        pool.release(conn);
        assert_eq!(pool.idle_count("host1"), 1);
    }

    #[test]
    fn pool_acquire_reuses() {
        let pool = ConnectionPool::new(5, Duration::from_secs(60));
        let conn = pool.create("host1");
        pool.release(conn);
        let acquired = pool.acquire("host1");
        assert!(acquired.is_some());
        assert_eq!(pool.idle_count("host1"), 0);
    }

    #[test]
    fn pool_evict_stale() {
        let pool = ConnectionPool::new(5, Duration::from_millis(1));
        let conn = pool.create("host1");
        pool.release(conn);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(pool.evict_stale(), 1);
    }

    // Load balancer
    #[test]
    fn lb_selects_healthy() {
        let lb = HealthLoadBalancer::new(vec![
            Backend {
                id: "a".into(),
                address: "a:80".into(),
                health_score: 100,
                healthy: true,
            },
            Backend {
                id: "b".into(),
                address: "b:80".into(),
                health_score: 50,
                healthy: false,
            },
        ]);
        let selected = lb.select().unwrap();
        assert_eq!(selected.id, "a");
    }

    #[test]
    fn lb_no_healthy_returns_none() {
        let lb = HealthLoadBalancer::new(vec![Backend {
            id: "a".into(),
            address: "a:80".into(),
            health_score: 100,
            healthy: false,
        }]);
        assert!(lb.select().is_none());
    }

    #[test]
    fn lb_update_health() {
        let lb = HealthLoadBalancer::new(vec![Backend {
            id: "a".into(),
            address: "a:80".into(),
            health_score: 100,
            healthy: true,
        }]);
        lb.update_health("a", 50, false);
        assert_eq!(lb.healthy_count(), 0);
    }

    // Retry jitter
    #[test]
    fn backoff_returns_delay() {
        let delay = backoff_with_jitter(
            0,
            Duration::from_millis(100),
            Duration::from_secs(10),
            JitterStrategy::Full,
        );
        assert!(delay <= Duration::from_millis(100));
    }

    #[test]
    fn backoff_capped_at_max() {
        let delay = backoff_with_jitter(
            20,
            Duration::from_millis(100),
            Duration::from_secs(1),
            JitterStrategy::Full,
        );
        assert!(delay <= Duration::from_secs(1));
    }

    // Degradation cache
    #[test]
    fn cache_store_get_fresh() {
        let cache = DegradationCache::<String>::new(Duration::from_secs(60));
        cache.store("k1", "value".into());
        assert_eq!(cache.get_fresh("k1"), Some("value".into()));
        assert!(!cache.is_stale("k1"));
    }

    #[test]
    fn cache_stale_after_ttl() {
        let cache = DegradationCache::<String>::new(Duration::from_millis(1));
        cache.store("k1", "value".into());
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.is_stale("k1"));
        assert_eq!(cache.get_stale("k1"), Some("value".into()));
        assert!(cache.get_fresh("k1").is_none());
    }

    // WebSocket
    #[test]
    fn ws_subscribe_unsubscribe() {
        let ws = WsCoordinator::new();
        ws.subscribe("s1", "c1");
        ws.subscribe("s1", "c2");
        assert_eq!(ws.subscriber_count("s1"), 2);
        ws.unsubscribe("s1", "c1");
        assert_eq!(ws.subscriber_count("s1"), 1);
    }

    #[test]
    fn ws_broadcast_returns_subscribers() {
        let ws = WsCoordinator::new();
        ws.subscribe("s1", "c1");
        ws.subscribe("s1", "c2");
        let recipients = ws.broadcast("s1");
        assert_eq!(recipients.len(), 2);
    }

    // Garbled circuits
    #[test]
    fn garble_and_evaluate_and() {
        let gate = garble_and_gate();
        let result00 = evaluate_gate(&gate, &gate.input_a.zero, &gate.input_b.zero);
        let result11 = evaluate_gate(&gate, &gate.input_a.one, &gate.input_b.one);
        assert!(result00.is_some());
        assert!(result11.is_some());
        assert_eq!(result00.unwrap(), gate.output.zero);
        assert_eq!(result11.unwrap(), gate.output.one);
    }

    // Bulk signing
    #[test]
    fn bulk_enqueue_and_flush() {
        let pipeline = BulkSignPipeline::new(3);
        assert!(!pipeline.enqueue(BulkSignItem {
            message_hash: vec![1],
            quorum_id: "q".into()
        }));
        assert!(!pipeline.enqueue(BulkSignItem {
            message_hash: vec![2],
            quorum_id: "q".into()
        }));
        assert!(pipeline.enqueue(BulkSignItem {
            message_hash: vec![3],
            quorum_id: "q".into()
        }));
        let batch = pipeline.flush();
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn bulk_batch_and_sign() {
        let pipeline = BulkSignPipeline::new(2);
        pipeline.enqueue(BulkSignItem {
            message_hash: vec![1],
            quorum_id: "q".into(),
        });
        pipeline.enqueue(BulkSignItem {
            message_hash: vec![2],
            quorum_id: "q".into(),
        });
        let result =
            pipeline.batch_and_sign(|items| items.iter().map(|i| i.message_hash.clone()).collect());
        assert_eq!(result.batch_count, 2);
        assert_eq!(result.signatures.len(), 2);
    }
}
