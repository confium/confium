//! Rate limiter — token bucket implementation for DoS protection.
//!
//! Limits request rates per client (or per any arbitrary key). Uses
//! the token bucket algorithm: tokens refill at a fixed rate up to a
//! capacity ceiling. Each request consumes one token.
//!
//! ## OCP design
//!
//! New rate-limiting algorithms (sliding window, leaky bucket) are
//! added by implementing the [`RateLimiter`] trait — no existing code
//! is modified.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Trait for rate limiters. Implementations decide whether a request
/// from `key` (typically a client ID or IP) should be allowed.
pub trait RateLimiter: Send + Sync {
    /// Check if a request is allowed. Consumes one token if allowed.
    /// Returns `true` if allowed, `false` if rate-limited.
    fn check(&self, key: &str) -> bool;

    /// Peek at remaining tokens without consuming. Returns the
    /// approximate number of available tokens (0 means limited).
    fn peek(&self, key: &str) -> u32;

    /// Reset the limiter state for a key (clears the bucket).
    fn reset(&self, key: &str);
}

/// Configuration for a token bucket rate limiter.
#[derive(Debug, Clone)]
pub struct TokenBucketConfig {
    /// Maximum tokens a bucket can hold.
    pub capacity: u32,
    /// Tokens added per second.
    pub refill_per_second: f64,
}

/// Token bucket rate limiter with per-key buckets.
pub struct TokenBucketRateLimiter {
    config: TokenBucketConfig,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucketRateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: TokenBucketConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Create a rate limiter with `capacity` tokens, refilling at
    /// `refill_per_second` tokens/second.
    pub fn with_rate(capacity: u32, refill_per_second: f64) -> Self {
        Self::new(TokenBucketConfig {
            capacity,
            refill_per_second,
        })
    }

    fn refill_bucket(&self, bucket: &mut Bucket) {
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let refilled = elapsed * self.config.refill_per_second;
        bucket.tokens = (bucket.tokens + refilled).min(self.config.capacity as f64);
        bucket.last_refill = now;
    }

    fn get_or_create_bucket(&self, key: &str) -> Bucket {
        Bucket {
            tokens: self.config.capacity as f64,
            last_refill: Instant::now(),
        }
    }
}

impl RateLimiter for TokenBucketRateLimiter {
    fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| self.get_or_create_bucket(key));
        self.refill_bucket(bucket);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn peek(&self, key: &str) -> u32 {
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| self.get_or_create_bucket(key));
        self.refill_bucket(bucket);
        bucket.tokens as u32
    }

    fn reset(&self, key: &str) {
        self.buckets.lock().unwrap().remove(key);
    }
}

/// A rate limiter that always allows. Useful for testing and
/// development environments where rate limiting is disabled.
pub struct NoopRateLimiter;

impl RateLimiter for NoopRateLimiter {
    fn check(&self, _key: &str) -> bool {
        true
    }
    fn peek(&self, _key: &str) -> u32 {
        u32::MAX
    }
    fn reset(&self, _key: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_until_capacity() {
        let limiter = TokenBucketRateLimiter::with_rate(5, 0.0);
        for _ in 0..5 {
            assert!(limiter.check("client-1"));
        }
        assert!(!limiter.check("client-1"));
    }

    #[test]
    fn separate_keys_have_separate_buckets() {
        let limiter = TokenBucketRateLimiter::with_rate(2, 0.0);
        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
        assert!(limiter.check("b"));
        assert!(limiter.check("b"));
        assert!(!limiter.check("a"));
        assert!(!limiter.check("b"));
    }

    #[test]
    fn noop_always_allows() {
        let limiter = NoopRateLimiter;
        for _ in 0..100 {
            assert!(limiter.check("anyone"));
        }
    }

    #[test]
    fn peek_does_not_consume() {
        let limiter = TokenBucketRateLimiter::with_rate(3, 0.0);
        assert_eq!(limiter.peek("k"), 3);
        assert_eq!(limiter.peek("k"), 3);
        limiter.check("k");
        assert_eq!(limiter.peek("k"), 2);
    }

    #[test]
    fn reset_clears_bucket() {
        let limiter = TokenBucketRateLimiter::with_rate(1, 0.0);
        assert!(limiter.check("k"));
        assert!(!limiter.check("k"));
        limiter.reset("k");
        assert!(limiter.check("k"));
    }

    #[test]
    fn refill_restores_tokens_over_time() {
        let limiter = TokenBucketRateLimiter::with_rate(1, 1000.0);
        assert!(limiter.check("k"));
        assert!(!limiter.check("k"));
        std::thread::sleep(Duration::from_millis(10));
        assert!(limiter.check("k"));
    }

    #[test]
    fn capacity_ceiling_prevents_overfill() {
        let limiter = TokenBucketRateLimiter::with_rate(3, 1000.0);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(limiter.peek("k"), 3);
    }

    #[test]
    fn new_key_starts_at_full_capacity() {
        let limiter = TokenBucketRateLimiter::with_rate(7, 1.0);
        assert_eq!(limiter.peek("fresh"), 7);
    }

    #[test]
    fn unknown_key_peek_creates_full_bucket() {
        let limiter = TokenBucketRateLimiter::with_rate(5, 0.0);
        assert_eq!(limiter.peek("unknown"), 5);
    }

    #[test]
    fn config_values_preserved() {
        let config = TokenBucketConfig {
            capacity: 10,
            refill_per_second: 2.5,
        };
        let limiter = TokenBucketRateLimiter::new(config);
        assert_eq!(limiter.peek("k"), 10);
    }
}
