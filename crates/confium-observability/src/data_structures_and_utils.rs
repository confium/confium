//! Probabilistic data structures + efficient primitives + crypto utilities.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// === Bloom Filter ===

pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
    count: AtomicU64,
}

impl BloomFilter {
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let num_bits = (-(expected_items as f64 * false_positive_rate.ln())
            / (std::f64::consts::LN_2.powi(2)))
        .ceil() as usize;
        let num_bits = num_bits.max(64);
        let num_hashes =
            ((num_bits as f64 / expected_items as f64) * std::f64::consts::LN_2).ceil() as usize;
        let num_hashes = num_hashes.max(1);
        let words = num_bits.div_ceil(64);
        Self {
            bits: vec![0u64; words],
            num_bits,
            num_hashes,
            count: AtomicU64::new(0),
        }
    }

    pub fn insert(&mut self, data: &[u8]) {
        let (h1, h2) = double_hash(data);
        for i in 0..self.num_hashes {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            let idx = (combined as usize) % self.num_bits;
            let word = idx / 64;
            let bit = idx % 64;
            self.bits[word] |= 1u64 << bit;
        }
        self.count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn contains(&self, data: &[u8]) -> bool {
        let (h1, h2) = double_hash(data);
        for i in 0..self.num_hashes {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            let idx = (combined as usize) % self.num_bits;
            let word = idx / 64;
            let bit = idx % 64;
            if self.bits[word] & (1u64 << bit) == 0 {
                return false;
            }
        }
        true
    }

    pub fn estimated_count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }
    pub fn num_hashes(&self) -> usize {
        self.num_hashes
    }
}

fn double_hash(data: &[u8]) -> (u64, u64) {
    let mut h1 = Sha256::new();
    h1.update(b"h1");
    h1.update(data);
    let r1 = h1.finalize();
    let mut h2 = Sha256::new();
    h2.update(b"h2");
    h2.update(data);
    let r2 = h2.finalize();
    (
        u64::from_be_bytes(r1[..8].try_into().unwrap()),
        u64::from_be_bytes(r2[..8].try_into().unwrap()),
    )
}

// === Count-Min Sketch ===

pub struct CountMinSketch {
    table: Vec<Vec<AtomicU64>>,
    width: usize,
    depth: usize,
}

impl CountMinSketch {
    pub fn new(width: usize, depth: usize) -> Self {
        Self {
            table: (0..depth)
                .map(|_| (0..width).map(|_| AtomicU64::new(0)).collect())
                .collect(),
            width,
            depth,
        }
    }

    pub fn add(&self, data: &[u8], count: u64) {
        for (d, row) in self.table.iter().enumerate() {
            let idx = hash_at_depth(data, d, self.width);
            row[idx].fetch_add(count, Ordering::SeqCst);
        }
    }

    pub fn estimate(&self, data: &[u8]) -> u64 {
        self.table
            .iter()
            .enumerate()
            .map(|(d, row)| {
                let idx = hash_at_depth(data, d, self.width);
                row[idx].load(Ordering::SeqCst)
            })
            .min()
            .unwrap_or(0)
    }
}

fn hash_at_depth(data: &[u8], depth: usize, width: usize) -> usize {
    let mut h = Sha256::new();
    h.update(depth.to_be_bytes());
    h.update(data);
    let result = h.finalize();
    u64::from_be_bytes(result[..8].try_into().unwrap()) as usize % width
}

// === Ring Buffer ===

pub struct RingBuffer<T: Clone> {
    data: VecDeque<T>,
    capacity: usize,
}

impl<T: Clone> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, item: T) {
        if self.data.len() >= self.capacity {
            self.data.pop_front();
        }
        self.data.push_back(item);
    }

    pub fn latest(&self) -> Option<&T> {
        self.data.back()
    }
    pub fn oldest(&self) -> Option<&T> {
        self.data.front()
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    pub fn is_full(&self) -> bool {
        self.data.len() == self.capacity
    }
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter()
    }
    pub fn clear(&mut self) {
        self.data.clear();
    }
    pub fn as_vec(&self) -> Vec<T> {
        self.data.iter().cloned().collect()
    }
}

// === Test Fixture Factory ===

pub struct TestFixtures;

impl TestFixtures {
    pub fn random_bytes(n: usize) -> Vec<u8> {
        use rand_core::{OsRng, RngCore};
        let mut buf = vec![0u8; n];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    pub fn random_hex(n: usize) -> String {
        hex::encode(Self::random_bytes(n))
    }

    pub fn random_message() -> Vec<u8> {
        Self::random_bytes(32)
    }

    pub fn random_session_id() -> String {
        format!("session-{}", hex::encode(Self::random_bytes(4)))
    }

    pub fn random_signer_id() -> String {
        format!("signer-{}", hex::encode(Self::random_bytes(4)))
    }

    pub fn random_quorum_id() -> String {
        format!("quorum-{}", hex::encode(Self::random_bytes(4)))
    }

    pub fn fake_signature() -> Vec<u8> {
        Self::random_bytes(64)
    }
    pub fn fake_share() -> Vec<u8> {
        Self::random_bytes(32)
    }
    pub fn fake_public_key() -> Vec<u8> {
        Self::random_bytes(33)
    }

    // make_session_request lives in confium-tc-core or confium-coordinator, not here.

    pub fn batch_messages(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut msg = vec![0u8; 32];
                msg[0] = i as u8;
                msg
            })
            .collect()
    }
}

// === HKDF (RFC 5869) ===

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC");
    mac.update(ikm);
    let result = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&result);
    prk
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while output.len() < length {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("HMAC");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();
        let take = previous.len().min(length - output.len());
        output.extend_from_slice(&previous[..take]);
        counter += 1;
    }
    output
}

pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

// === Key Wrapping (RFC 3394 style simplified) ===

pub fn key_wrap(kek: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    // Simplified: XOR-based wrapping with integrity
    let mut mac = Hmac::<Sha256>::new_from_slice(kek).expect("HMAC");
    mac.update(plaintext);
    let tag = mac.finalize().into_bytes();
    let mut wrapped = Vec::with_capacity(plaintext.len() + 32);
    for (i, &b) in plaintext.iter().enumerate() {
        wrapped.push(b ^ kek[i % 32]);
    }
    wrapped.extend_from_slice(&tag[..16]);
    wrapped
}

pub fn key_unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 16 {
        return None;
    }
    let body = &wrapped[..wrapped.len() - 16];
    let tag = &wrapped[wrapped.len() - 16..];
    let unwrapped: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ kek[i % 32])
        .collect();
    let mut mac = Hmac::<Sha256>::new_from_slice(kek).expect("HMAC");
    mac.update(&unwrapped);
    let expected = &mac.finalize().into_bytes()[..16];
    if tag == expected {
        Some(unwrapped)
    } else {
        None
    }
}

// === Secure File Deletion ===

pub fn secure_overwrite(data: &mut [u8]) {
    // Multi-pass overwrite: zeros, ones, random
    for b in data.iter_mut() {
        *b = 0x00;
    }
    for b in data.iter_mut() {
        *b = 0xFF;
    }
    use rand_core::{OsRng, RngCore};
    for chunk in data.chunks_mut(1) {
        let mut buf = [0u8; 1];
        OsRng.fill_bytes(&mut buf);
        chunk[0] = buf[0];
    }
}

pub struct SecureBuffer {
    data: Vec<u8>,
    zeroized: bool,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            zeroized: false,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn zeroize(&mut self) {
        if !self.zeroized {
            secure_overwrite(&mut self.data);
            self.zeroized = true;
        }
    }

    pub fn is_zeroized(&self) -> bool {
        self.zeroized
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        if !self.zeroized {
            secure_overwrite(&mut self.data);
        }
    }
}

// === Entropy Pool Monitor ===

pub struct EntropyMonitor {
    samples: Mutex<VecDeque<u32>>,
    max_samples: usize,
    min_threshold: u32,
    alerts: AtomicU64,
}

impl EntropyMonitor {
    pub fn new(max_samples: usize, min_threshold: u32) -> Self {
        Self {
            samples: Mutex::new(VecDeque::with_capacity(max_samples)),
            max_samples,
            min_threshold,
            alerts: AtomicU64::new(0),
        }
    }

    pub fn record(&self, entropy_bits: u32) {
        let mut samples = self.samples.lock().unwrap();
        if samples.len() >= self.max_samples {
            samples.pop_front();
        }
        samples.push_back(entropy_bits);
        if entropy_bits < self.min_threshold {
            self.alerts.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn latest(&self) -> Option<u32> {
        self.samples.lock().unwrap().back().copied()
    }
    pub fn average(&self) -> f64 {
        let s = self.samples.lock().unwrap();
        if s.is_empty() {
            return 0.0;
        }
        s.iter().sum::<u32>() as f64 / s.len() as f64
    }
    pub fn min(&self) -> Option<u32> {
        self.samples.lock().unwrap().iter().copied().min()
    }
    pub fn alert_count(&self) -> u64 {
        self.alerts.load(Ordering::SeqCst)
    }
    pub fn is_low(&self) -> bool {
        self.latest()
            .map(|e| e < self.min_threshold)
            .unwrap_or(false)
    }
    pub fn sample_count(&self) -> usize {
        self.samples.lock().unwrap().len()
    }
}

// === Burst Token Bucket ===

pub struct BurstTokenBucket {
    tokens: Mutex<f64>,
    capacity: f64,
    refill_rate: f64, // tokens per second
    burst_capacity: f64,
    last_refill: Mutex<std::time::Instant>,
}

impl BurstTokenBucket {
    pub fn new(sustained_rate: f64, burst_multiplier: f64) -> Self {
        let capacity = sustained_rate * burst_multiplier;
        Self {
            tokens: Mutex::new(capacity),
            capacity,
            refill_rate: sustained_rate,
            burst_capacity: capacity,
            last_refill: Mutex::new(std::time::Instant::now()),
        }
    }

    fn refill(&self) {
        let mut tokens = self.tokens.lock().unwrap();
        let mut last = self.last_refill.lock().unwrap();
        let elapsed = last.elapsed().as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_rate).min(self.capacity);
        *last = std::time::Instant::now();
    }

    pub fn try_consume(&self, cost: f64) -> bool {
        self.refill();
        let mut tokens = self.tokens.lock().unwrap();
        if *tokens >= cost {
            *tokens -= cost;
            true
        } else {
            false
        }
    }

    pub fn available_tokens(&self) -> f64 {
        self.refill();
        *self.tokens.lock().unwrap()
    }

    pub fn burst_capacity(&self) -> f64 {
        self.burst_capacity
    }
    pub fn sustained_rate(&self) -> f64 {
        self.refill_rate
    }
}

// === Concurrent Test Runner ===

pub struct ConcurrentTestRunner {
    results: Mutex<Vec<ConcTestResult>>,
}

#[derive(Debug, Clone)]
pub struct ConcTestResult {
    pub name: String,
    pub passed: bool,
    pub duration_micros: u64,
}

impl ConcurrentTestRunner {
    pub fn new() -> Self {
        Self {
            results: Mutex::new(Vec::new()),
        }
    }

    pub fn run<F>(&self, name: &str, test_fn: F) -> bool
    where
        F: FnOnce() -> bool + Send + 'static,
    {
        let start = std::time::Instant::now();
        let passed = test_fn();
        let duration = start.elapsed().as_micros() as u64;
        self.results.lock().unwrap().push(ConcTestResult {
            name: name.into(),
            passed,
            duration_micros: duration,
        });
        passed
    }

    pub fn run_concurrent<F>(&self, tests: Vec<(&str, F)>) -> usize
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        let passed_count = std::sync::Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for (name, test_fn) in tests {
            let pc = std::sync::Arc::clone(&passed_count);
            let results = std::sync::Arc::new(Mutex::new(Vec::new()));
            let r2 = std::sync::Arc::clone(&results);
            let name = name.to_string();
            handles.push(std::thread::spawn(move || {
                let start = std::time::Instant::now();
                let passed = test_fn();
                let duration = start.elapsed().as_micros() as u64;
                r2.lock().unwrap().push(ConcTestResult {
                    name,
                    passed,
                    duration_micros: duration,
                });
                if passed {
                    pc.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        let _total = handles.len();
        for h in handles {
            let _ = h.join();
        }
        passed_count.load(Ordering::SeqCst) as usize
    }

    pub fn results(&self) -> Vec<ConcTestResult> {
        self.results.lock().unwrap().clone()
    }
    pub fn total(&self) -> usize {
        self.results.lock().unwrap().len()
    }
    pub fn passed(&self) -> usize {
        self.results
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.passed)
            .count()
    }
    pub fn failed(&self) -> usize {
        self.total() - self.passed()
    }
    pub fn avg_duration_micros(&self) -> f64 {
        let r = self.results.lock().unwrap();
        if r.is_empty() {
            return 0.0;
        }
        r.iter().map(|r| r.duration_micros as f64).sum::<f64>() / r.len() as f64
    }
}

impl Default for ConcurrentTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

// === SPSC Channel ===

pub struct SpscSender<T> {
    shared: std::sync::Arc<SpscShared<T>>,
}
pub struct SpscReceiver<T> {
    shared: std::sync::Arc<SpscShared<T>>,
}

struct SpscShared<T> {
    buffer: Mutex<VecDeque<T>>,
    capacity: usize,
    total_sent: AtomicU64,
    total_received: AtomicU64,
}

pub fn spsc_channel<T>(capacity: usize) -> (SpscSender<T>, SpscReceiver<T>) {
    let shared = std::sync::Arc::new(SpscShared {
        buffer: Mutex::new(VecDeque::with_capacity(capacity)),
        capacity,
        total_sent: AtomicU64::new(0),
        total_received: AtomicU64::new(0),
    });
    (
        SpscSender {
            shared: std::sync::Arc::clone(&shared),
        },
        SpscReceiver { shared },
    )
}

impl<T> SpscSender<T> {
    pub fn send(&self, item: T) -> bool {
        let mut buf = self.shared.buffer.lock().unwrap();
        if buf.len() >= self.shared.capacity {
            return false;
        }
        buf.push_back(item);
        self.shared.total_sent.fetch_add(1, Ordering::SeqCst);
        true
    }
    pub fn total_sent(&self) -> u64 {
        self.shared.total_sent.load(Ordering::SeqCst)
    }
}

impl<T> SpscReceiver<T> {
    pub fn recv(&self) -> Option<T> {
        let item = self.shared.buffer.lock().unwrap().pop_front();
        if item.is_some() {
            self.shared.total_received.fetch_add(1, Ordering::SeqCst);
        }
        item
    }
    pub fn len(&self) -> usize {
        self.shared.buffer.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn total_received(&self) -> u64 {
        self.shared.total_received.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bloom filter
    #[test]
    fn bloom_insert_and_contains() {
        let mut bf = BloomFilter::new(1000, 0.01);
        bf.insert(b"apple");
        bf.insert(b"banana");
        assert!(bf.contains(b"apple"));
        assert!(bf.contains(b"banana"));
    }

    #[test]
    fn bloom_absent_not_present() {
        let mut bf = BloomFilter::new(1000, 0.01);
        bf.insert(b"present");
        // With high probability, "absent" is not present
        let false_positives = (0..100)
            .filter(|i| bf.contains(format!("absent-{i}").as_bytes()))
            .count();
        assert!(false_positives < 10); // < 10% false positive rate
    }

    #[test]
    fn bloom_count() {
        let mut bf = BloomFilter::new(100, 0.05);
        for i in 0..50 {
            bf.insert(format!("item-{i}").as_bytes());
        }
        assert_eq!(bf.estimated_count(), 50);
    }

    // Count-Min sketch
    #[test]
    fn cms_estimate_frequency() {
        let cms = CountMinSketch::new(1000, 5);
        for _ in 0..10 {
            cms.add(b"popular", 1);
        }
        for _ in 0..3 {
            cms.add(b"rare", 1);
        }
        assert!(cms.estimate(b"popular") >= 10);
        assert!(cms.estimate(b"rare") >= 3);
    }

    #[test]
    fn cms_unknown_is_low() {
        let cms = CountMinSketch::new(1000, 5);
        cms.add(b"x", 1);
        assert!(cms.estimate(b"unknown") <= 5);
    }

    // Ring buffer
    #[test]
    fn ring_buffer_evicts_oldest() {
        let mut rb = RingBuffer::new(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        rb.push(4);
        assert_eq!(rb.len(), 3);
        assert_eq!(*rb.oldest().unwrap(), 2);
        assert_eq!(*rb.latest().unwrap(), 4);
    }

    #[test]
    fn ring_buffer_iter() {
        let mut rb = RingBuffer::new(5);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        let v: Vec<i32> = rb.iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    // Test fixtures
    #[test]
    fn fixtures_random_bytes() {
        let b1 = TestFixtures::random_bytes(32);
        let b2 = TestFixtures::random_bytes(32);
        assert_eq!(b1.len(), 32);
        assert_ne!(b1, b2);
    }

    #[test]
    fn fixtures_session_id() {
        let id = TestFixtures::random_session_id();
        assert!(id.starts_with("session-"));
    }

    #[test]
    fn fixtures_batch_messages() {
        let msgs = TestFixtures::batch_messages(5);
        assert_eq!(msgs.len(), 5);
        assert_eq!(msgs[0][0], 0);
        assert_eq!(msgs[4][0], 4);
    }

    // HKDF
    #[test]
    fn hkdf_extract_produces_prk() {
        let prk = hkdf_extract(b"salt", b"ikm");
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn hkdf_expand_produces_output() {
        let prk = [0x42u8; 32];
        let okm = hkdf_expand(&prk, b"info", 64);
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn hkdf_full_round_trips() {
        let okm1 = hkdf(b"salt", b"ikm", b"info", 32);
        let okm2 = hkdf(b"salt", b"ikm", b"info", 32);
        assert_eq!(okm1, okm2); // deterministic
    }

    #[test]
    fn hkdf_different_info_different_output() {
        let okm1 = hkdf(b"s", b"ikm", b"info1", 32);
        let okm2 = hkdf(b"s", b"ikm", b"info2", 32);
        assert_ne!(okm1, okm2);
    }

    // Key wrapping
    #[test]
    fn key_wrap_unwrap_round_trips() {
        let kek = [0x42u8; 32];
        let plaintext = TestFixtures::random_bytes(32);
        let wrapped = key_wrap(&kek, &plaintext);
        let unwrapped = key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn key_wrap_tampered_rejected() {
        let kek = [0x42u8; 32];
        let mut wrapped = key_wrap(&kek, b"secret");
        wrapped[0] ^= 0xFF;
        assert!(key_unwrap(&kek, &wrapped).is_none());
    }

    // Secure deletion
    #[test]
    fn secure_overwrite_changes_data() {
        let mut data = vec![0xAA; 32];
        secure_overwrite(&mut data);
        assert!(data.iter().any(|&b| b != 0xAA));
    }

    #[test]
    fn secure_buffer_zeroize() {
        let mut buf = SecureBuffer::new(vec![0x42; 32]);
        assert!(!buf.is_zeroized());
        buf.zeroize();
        assert!(buf.is_zeroized());
        // The buffer must have changed from the initial all-0x42 state.
        // (We can't assert "no byte is 0x42" because secure_overwrite's
        // final pass uses OsRng, which can return any byte value.)
        let unchanged = buf.as_slice().iter().filter(|&&b| b == 0x42).count();
        assert!(
            unchanged < 32,
            "buffer was not overwritten (still all 0x42)"
        );
    }

    // Entropy monitor
    #[test]
    fn entropy_monitor_records() {
        let mon = EntropyMonitor::new(10, 100);
        mon.record(256);
        mon.record(128);
        mon.record(64);
        assert_eq!(mon.sample_count(), 3);
        assert_eq!(mon.latest(), Some(64));
        assert!(mon.average() > 0.0);
    }

    #[test]
    fn entropy_monitor_alerts() {
        let mon = EntropyMonitor::new(10, 100);
        mon.record(256);
        mon.record(32);
        assert_eq!(mon.alert_count(), 1);
        assert!(mon.is_low());
    }

    // Burst token bucket
    #[test]
    fn burst_bucket_allows_initial_burst() {
        let bucket = BurstTokenBucket::new(10.0, 5.0); // 10/s sustained, 50 burst
        assert!(bucket.try_consume(50.0)); // initial burst
        assert!(!bucket.try_consume(1.0)); // empty
    }

    #[test]
    fn burst_bucket_refills_over_time() {
        let bucket = BurstTokenBucket::new(1000.0, 1.0); // fast refill
        bucket.try_consume(1000.0);
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(bucket.try_consume(1.0)); // refilled
    }

    // Concurrent test runner
    #[test]
    fn concurrent_runner_runs_tests() {
        let runner = ConcurrentTestRunner::new();
        runner.run("test1", || true);
        runner.run("test2", || false);
        assert_eq!(runner.total(), 2);
        assert_eq!(runner.passed(), 1);
        assert_eq!(runner.failed(), 1);
    }

    #[test]
    fn concurrent_runner_parallel() {
        type TestFn = (&'static str, fn() -> bool);
        let runner = ConcurrentTestRunner::new();
        let tests: Vec<TestFn> = vec![
            ("t1", || true),
            ("t2", || true),
            ("t3", || true),
            ("t4", || false),
        ];
        let passed = runner.run_concurrent(tests);
        assert_eq!(passed, 3);
    }

    // SPSC channel
    #[test]
    fn spsc_send_recv() {
        let (tx, rx) = spsc_channel::<i32>(10);
        assert!(tx.send(42));
        assert_eq!(rx.recv(), Some(42));
        assert!(rx.is_empty());
    }

    #[test]
    fn spsc_respects_capacity() {
        let (tx, _rx) = spsc_channel::<i32>(2);
        assert!(tx.send(1));
        assert!(tx.send(2));
        assert!(!tx.send(3)); // full
    }

    #[test]
    fn spsc_ordering() {
        let (tx, rx) = spsc_channel::<i32>(10);
        tx.send(1);
        tx.send(2);
        tx.send(3);
        assert_eq!(rx.recv(), Some(1));
        assert_eq!(rx.recv(), Some(2));
        assert_eq!(rx.recv(), Some(3));
    }

    #[test]
    fn spsc_counters() {
        let (tx, rx) = spsc_channel::<i32>(10);
        tx.send(1);
        tx.send(2);
        rx.recv();
        assert_eq!(tx.total_sent(), 2);
        assert_eq!(rx.total_received(), 1);
    }
}
