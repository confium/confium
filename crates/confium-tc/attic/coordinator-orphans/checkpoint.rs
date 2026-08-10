//! Session checkpoint manager — periodic WAL checkpointing.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for checkpointing.
#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    /// How often to checkpoint.
    pub interval: Duration,
    /// Maximum entries before forcing a checkpoint.
    pub max_entries_before_checkpoint: usize,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(300),
            max_entries_before_checkpoint: 1000,
        }
    }
}

/// Tracks when the next checkpoint should occur.
pub struct CheckpointManager {
    config: CheckpointConfig,
    last_checkpoint: Mutex<Instant>,
    entries_since_checkpoint: Mutex<usize>,
    total_checkpoints: Mutex<u64>,
}

impl CheckpointManager {
    pub fn new(config: CheckpointConfig) -> Self {
        Self {
            config,
            last_checkpoint: Mutex::new(Instant::now()),
            entries_since_checkpoint: Mutex::new(0),
            total_checkpoints: Mutex::new(0),
        }
    }

    /// Record that a WAL entry was appended.
    pub fn record_entry(&self) {
        *self.entries_since_checkpoint.lock().unwrap() += 1;
    }

    /// Should a checkpoint be taken now?
    pub fn should_checkpoint(&self) -> bool {
        let elapsed = self.last_checkpoint.lock().unwrap().elapsed();
        let entries = *self.entries_since_checkpoint.lock().unwrap();
        elapsed >= self.config.interval || entries >= self.config.max_entries_before_checkpoint
    }

    /// Record that a checkpoint was taken.
    pub fn checkpoint_taken(&self) {
        *self.last_checkpoint.lock().unwrap() = Instant::now();
        *self.entries_since_checkpoint.lock().unwrap() = 0;
        *self.total_checkpoints.lock().unwrap() += 1;
    }

    /// Total checkpoints taken since start.
    pub fn total_checkpoints(&self) -> u64 {
        *self.total_checkpoints.lock().unwrap()
    }

    /// Entries since last checkpoint.
    pub fn entries_since_checkpoint(&self) -> usize {
        *self.entries_since_checkpoint.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_interval_5min() {
        let config = CheckpointConfig::default();
        assert_eq!(config.interval, Duration::from_secs(300));
    }

    #[test]
    fn no_checkpoint_needed_initially() {
        let mgr = CheckpointManager::new(CheckpointConfig::default());
        assert!(!mgr.should_checkpoint());
    }

    #[test]
    fn checkpoint_after_max_entries() {
        let config = CheckpointConfig {
            interval: Duration::from_secs(3600),
            max_entries_before_checkpoint: 5,
        };
        let mgr = CheckpointManager::new(config);
        for _ in 0..5 {
            mgr.record_entry();
        }
        assert!(mgr.should_checkpoint());
    }

    #[test]
    fn checkpoint_resets_counter() {
        let config = CheckpointConfig {
            interval: Duration::from_secs(3600),
            max_entries_before_checkpoint: 3,
        };
        let mgr = CheckpointManager::new(config);
        for _ in 0..3 {
            mgr.record_entry();
        }
        assert!(mgr.should_checkpoint());
        mgr.checkpoint_taken();
        assert!(!mgr.should_checkpoint());
        assert_eq!(mgr.entries_since_checkpoint(), 0);
    }

    #[test]
    fn total_checkpoints_increments() {
        let mgr = CheckpointManager::new(CheckpointConfig::default());
        assert_eq!(mgr.total_checkpoints(), 0);
        mgr.checkpoint_taken();
        mgr.checkpoint_taken();
        assert_eq!(mgr.total_checkpoints(), 2);
    }

    #[test]
    fn entries_accumulate() {
        let mgr = CheckpointManager::new(CheckpointConfig::default());
        mgr.record_entry();
        mgr.record_entry();
        mgr.record_entry();
        assert_eq!(mgr.entries_since_checkpoint(), 3);
    }
}
