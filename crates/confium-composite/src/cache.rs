//! LRU cache for signature verification results.
//!
//! Avoids re-verifying identical (algorithm, public_key, message,
//! signature) tuples. Thread-safe via `Mutex`. LRU eviction by
//! entry count.
//!
//! ## Usage
//!
//! ```no_run
//! use confium_composite::cache::VerificationCache;
//!
//! let cache = VerificationCache::new(1024);
//! // First call: miss → verify → cache result
//! // Second call: hit → return cached result
//! ```

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// Cache key — SHA-256 of the verification inputs.
type CacheKey = [u8; 32];

/// Entry in the LRU cache: the verification result and a sequence
/// number for LRU eviction.
struct CacheEntry {
    verified: bool,
    seq: u64,
}

/// Thread-safe LRU cache for signature verification results.
pub struct VerificationCache {
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    entries: HashMap<CacheKey, CacheEntry>,
    max_entries: usize,
    next_seq: u64,
}

impl VerificationCache {
    /// Create a new cache with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                entries: HashMap::with_capacity(max_entries),
                max_entries,
                next_seq: 0,
            }),
        }
    }

    /// Look up a cached result. Returns `Some(verified)` on hit,
    /// `None` on miss.
    pub fn get(
        &self,
        algorithm: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Option<bool> {
        let key = make_key(algorithm, public_key, message, signature);
        let mut inner = self.inner.lock().unwrap();
        let next_seq = inner.next_seq;
        inner.next_seq += 1;
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.seq = next_seq;
            Some(entry.verified)
        } else {
            None
        }
    }

    /// Store a verification result.
    pub fn put(
        &self,
        algorithm: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        verified: bool,
    ) {
        let key = make_key(algorithm, public_key, message, signature);
        let mut inner = self.inner.lock().unwrap();
        let seq = inner.next_seq;
        inner.next_seq += 1;

        inner.entries.insert(
            key,
            CacheEntry {
                verified,
                seq,
            },
        );

        if inner.entries.len() > inner.max_entries {
            evict_oldest(&mut inner.entries);
        }
    }

    /// Current entry count.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.inner.lock().unwrap().entries.clear();
    }
}

impl Default for VerificationCache {
    fn default() -> Self {
        Self::new(1024)
    }
}

fn make_key(algorithm: &str, public_key: &[u8], message: &[u8], signature: &[u8]) -> CacheKey {
    let mut hasher = Sha256::new();
    hasher.update(algorithm.as_bytes());
    hasher.update(public_key);
    hasher.update(message);
    hasher.update(signature);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn evict_oldest(entries: &mut HashMap<CacheKey, CacheEntry>) {
    if let Some((&oldest_key, _)) = entries.iter().min_by_key(|(_, v)| v.seq) {
        entries.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_returns_none() {
        let cache = VerificationCache::new(100);
        assert_eq!(cache.get("Ed25519", &[1; 32], &[2; 32], &[3; 64]), None);
    }

    #[test]
    fn put_then_get_returns_cached() {
        let cache = VerificationCache::new(100);
        cache.put("Ed25519", &[1; 32], &[2; 32], &[3; 64], true);
        assert_eq!(cache.get("Ed25519", &[1; 32], &[2; 32], &[3; 64]), Some(true));
    }

    #[test]
    fn different_message_is_miss() {
        let cache = VerificationCache::new(100);
        cache.put("Ed25519", &[1; 32], &[2; 32], &[3; 64], true);
        assert_eq!(cache.get("Ed25519", &[1; 32], &[9; 32], &[3; 64]), None);
    }

    #[test]
    fn different_signature_is_miss() {
        let cache = VerificationCache::new(100);
        cache.put("Ed25519", &[1; 32], &[2; 32], &[3; 64], true);
        assert_eq!(cache.get("Ed25519", &[1; 32], &[2; 32], &[9; 64]), None);
    }

    #[test]
    fn lru_eviction_removes_oldest() {
        let cache = VerificationCache::new(3);
        cache.put("a", &[1], &[1], &[1], true);
        cache.put("b", &[2], &[2], &[2], true);
        cache.put("c", &[3], &[3], &[3], true);

        // Access "a" to make it more recent than "b"
        cache.get("a", &[1], &[1], &[1]);

        // Insert "d" → should evict "b" (least recently used)
        cache.put("d", &[4], &[4], &[4], true);

        assert_eq!(cache.get("a", &[1], &[1], &[1]), Some(true));
        assert_eq!(cache.get("b", &[2], &[2], &[2]), None); // evicted
        assert_eq!(cache.get("c", &[3], &[3], &[3]), Some(true));
        assert_eq!(cache.get("d", &[4], &[4], &[4]), Some(true));
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn clear_empties_cache() {
        let cache = VerificationCache::new(100);
        cache.put("a", &[1], &[1], &[1], true);
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn overwrite_updates_value() {
        let cache = VerificationCache::new(100);
        cache.put("Ed25519", &[1], &[2], &[3], false);
        assert_eq!(cache.get("Ed25519", &[1], &[2], &[3]), Some(false));
        cache.put("Ed25519", &[1], &[2], &[3], true);
        assert_eq!(cache.get("Ed25519", &[1], &[2], &[3]), Some(true));
    }

    #[test]
    fn capacity_one_always_evicts() {
        let cache = VerificationCache::new(1);
        cache.put("a", &[1], &[1], &[1], true);
        assert_eq!(cache.len(), 1);
        cache.put("b", &[2], &[2], &[2], true);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("a", &[1], &[1], &[1]), None);
        assert_eq!(cache.get("b", &[2], &[2], &[2]), Some(true));
    }

    #[test]
    fn default_capacity_is_1024() {
        let cache = VerificationCache::default();
        assert_eq!(cache.len(), 0);
        for i in 0..100 {
            cache.put("alg", &[i], &[i], &[i], true);
        }
        assert_eq!(cache.len(), 100);
    }

    #[test]
    fn thread_safe_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(VerificationCache::new(100));
        let mut handles = Vec::new();

        for i in 0..4 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for j in 0..10 {
                    let val = i * 10 + j;
                    cache.put("alg", &[val as u8], &[val as u8], &[val as u8], true);
                    cache.get("alg", &[val as u8], &[val as u8], &[val as u8]);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        assert!(cache.len() <= 100);
    }
}
