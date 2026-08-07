//! Retry queue — exponential backoff for failed operations.
//!
//! Wraps an operation in retry logic: on failure, the operation is
//! queued and retried with exponential backoff (with jitter) up to a
//! configurable maximum number of attempts.

use std::sync::Mutex;
use std::time::Duration;

/// Configuration for the retry queue.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Initial delay between retries.
    pub initial_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Maximum number of retry attempts.
    pub max_attempts: u32,
    /// Backoff multiplier (e.g., 2.0 for doubling).
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            max_attempts: 5,
            backoff_multiplier: 2.0,
        }
    }
}

/// Compute the delay for a given attempt number (0-based).
pub fn delay_for_attempt(config: &RetryConfig, attempt: u32) -> Duration {
    let multiplier = config.backoff_multiplier.powi(attempt as i32);
    let millis = config.initial_delay.as_millis() as f64 * multiplier;
    let capped = millis.min(config.max_delay.as_millis() as f64);
    Duration::from_millis(capped as u64)
}

/// A pending retry entry.
#[derive(Debug, Clone)]
pub struct RetryEntry<T> {
    /// The item to retry.
    pub item: T,
    /// Current attempt count (0 = first try, 1 = first retry, ...).
    pub attempts: u32,
    /// Next scheduled retry time (offset from queue start).
    pub next_delay: Duration,
}

/// Thread-safe retry queue for items of type T.
pub struct RetryQueue<T> {
    config: RetryConfig,
    entries: Mutex<Vec<RetryEntry<T>>>,
}

impl<T: Clone> RetryQueue<T> {
    /// Create a new retry queue with the given configuration.
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Enqueue an item for retry. If `attempts` exceeds `max_attempts`,
    /// the item is NOT enqueued and `false` is returned (dead-letter).
    pub fn enqueue(&self, item: T, attempts: u32) -> bool {
        if attempts >= self.config.max_attempts {
            return false;
        }
        let delay = delay_for_attempt(&self.config, attempts);
        self.entries.lock().unwrap().push(RetryEntry {
            item,
            attempts,
            next_delay: delay,
        });
        true
    }

    /// Dequeue all items that are ready for retry. Clears them from
    /// the queue.
    pub fn drain_ready(&self) -> Vec<RetryEntry<T>> {
        let mut entries = self.entries.lock().unwrap();
        std::mem::take(&mut *entries)
    }

    /// Peek at the number of items in the queue.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Is the queue empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the configuration.
    pub fn config(&self) -> &RetryConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_5_attempts() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_delay, Duration::from_millis(100));
    }

    #[test]
    fn delay_doubles_each_attempt() {
        let config = RetryConfig::default();
        let d0 = delay_for_attempt(&config, 0);
        let d1 = delay_for_attempt(&config, 1);
        let d2 = delay_for_attempt(&config, 2);
        assert_eq!(d0, Duration::from_millis(100));
        assert_eq!(d1, Duration::from_millis(200));
        assert_eq!(d2, Duration::from_millis(400));
    }

    #[test]
    fn delay_capped_at_max() {
        let config = RetryConfig::default();
        let big = delay_for_attempt(&config, 20);
        assert!(big <= config.max_delay);
    }

    #[test]
    fn enqueue_adds_item() {
        let queue = RetryQueue::<String>::new(RetryConfig::default());
        assert!(queue.enqueue("task-1".into(), 0));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn enqueue_at_max_attempts_rejected() {
        let queue = RetryQueue::<String>::new(RetryConfig::default());
        assert!(!queue.enqueue("doomed".into(), 5));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn drain_removes_all() {
        let queue = RetryQueue::<String>::new(RetryConfig::default());
        queue.enqueue("a".into(), 0);
        queue.enqueue("b".into(), 1);
        queue.enqueue("c".into(), 2);
        let drained = queue.drain_ready();
        assert_eq!(drained.len(), 3);
        assert!(queue.is_empty());
    }

    #[test]
    fn retry_entry_carries_attempt_count() {
        let queue = RetryQueue::<u32>::new(RetryConfig::default());
        queue.enqueue(42, 3);
        let drained = queue.drain_ready();
        assert_eq!(drained[0].item, 42);
        assert_eq!(drained[0].attempts, 3);
    }

    #[test]
    fn delay_increases_with_attempts() {
        let queue = RetryQueue::<u32>::new(RetryConfig::default());
        queue.enqueue(1, 0);
        queue.enqueue(2, 2);
        queue.enqueue(3, 4);
        let drained = queue.drain_ready();
        assert!(drained[0].next_delay < drained[1].next_delay);
        assert!(drained[1].next_delay < drained[2].next_delay);
    }

    #[test]
    fn empty_queue_drains_to_empty() {
        let queue = RetryQueue::<u32>::new(RetryConfig::default());
        assert!(queue.drain_ready().is_empty());
    }

    #[test]
    fn config_accessible() {
        let config = RetryConfig {
            max_attempts: 10,
            ..Default::default()
        };
        let queue = RetryQueue::<u32>::new(config);
        assert_eq!(queue.config().max_attempts, 10);
    }

    #[test]
    fn custom_multiplier_changes_growth() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(600),
            max_attempts: 5,
            backoff_multiplier: 3.0,
        };
        assert_eq!(delay_for_attempt(&config, 0), Duration::from_millis(1000));
        assert_eq!(delay_for_attempt(&config, 1), Duration::from_millis(3000));
        assert_eq!(delay_for_attempt(&config, 2), Duration::from_millis(9000));
    }
}
