//! Backpressure — limits concurrent active sessions.
//!
//! When the coordinator reaches `max_active_sessions`, new session
//! creation requests are rejected with [`BackpressureError::AtCapacity`].
//! This protects against memory exhaustion under load.
//!
//! Existing sessions continue to be processed; only new ones are
//! rejected until capacity frees up.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Configuration for backpressure.
#[derive(Debug, Clone)]
pub struct BackpressureConfig {
    /// Maximum simultaneous active sessions. 0 = unlimited.
    pub max_active_sessions: usize,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            max_active_sessions: 100,
        }
    }
}

/// Errors from backpressure enforcement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackpressureError {
    /// Coordinator is at capacity.
    #[error("at capacity: {active}/{max}")]
    AtCapacity {
        /// Currently active sessions.
        active: usize,
        /// Maximum allowed.
        max: usize,
    },
}

/// Backpressure gate — tracks active sessions and enforces the limit.
pub struct BackpressureGate {
    config: BackpressureConfig,
    active: AtomicUsize,
}

impl BackpressureGate {
    /// Create a new gate with the given configuration.
    pub fn new(config: BackpressureConfig) -> Self {
        Self {
            config,
            active: AtomicUsize::new(0),
        }
    }

    /// Current active session count.
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Maximum allowed sessions.
    pub fn max_sessions(&self) -> usize {
        self.config.max_active_sessions
    }

    /// Try to acquire a slot. Returns `Ok(())` if a slot was acquired
    /// (active count incremented), or `Err(AtCapacity)` if the
    /// coordinator is full.
    pub fn try_acquire(&self) -> Result<ActiveSlot, BackpressureError> {
        let max = self.config.max_active_sessions;
        if max == 0 {
            return Ok(ActiveSlot {
                gate: self,
                unlimited: true,
            });
        }
        let current = self.active.fetch_add(1, Ordering::SeqCst);
        if current >= max {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return Err(BackpressureError::AtCapacity {
                active: current,
                max,
            });
        }
        Ok(ActiveSlot {
            gate: self,
            unlimited: false,
        })
    }

    /// Release a slot (decrement active count).
    fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    /// Is the coordinator at capacity?
    pub fn is_at_capacity(&self) -> bool {
        let max = self.config.max_active_sessions;
        max > 0 && self.active_count() >= max
    }
}

/// RAII guard for an acquired backpressure slot. When dropped, the
/// slot is automatically released.
pub struct ActiveSlot<'a> {
    gate: &'a BackpressureGate,
    unlimited: bool,
}

impl<'a> std::fmt::Debug for ActiveSlot<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveSlot")
            .field("unlimited", &self.unlimited)
            .finish()
    }
}

impl<'a> Drop for ActiveSlot<'a> {
    fn drop(&mut self) {
        if !self.unlimited {
            self.gate.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_is_100() {
        let gate = BackpressureGate::new(BackpressureConfig::default());
        assert_eq!(gate.max_sessions(), 100);
    }

    #[test]
    fn acquire_increments_count() {
        let gate = BackpressureGate::new(BackpressureConfig {
            max_active_sessions: 5,
        });
        assert_eq!(gate.active_count(), 0);
        let slot = gate.try_acquire().unwrap();
        assert_eq!(gate.active_count(), 1);
        drop(slot);
        assert_eq!(gate.active_count(), 0);
    }

    #[test]
    fn at_capacity_rejects() {
        let gate = BackpressureGate::new(BackpressureConfig {
            max_active_sessions: 2,
        });
        let _s1 = gate.try_acquire().unwrap();
        let _s2 = gate.try_acquire().unwrap();
        let result = gate.try_acquire();
        assert_eq!(
            result.unwrap_err(),
            BackpressureError::AtCapacity {
                active: 2,
                max: 2
            }
        );
    }

    #[test]
    fn release_allows_new_acquire() {
        let gate = BackpressureGate::new(BackpressureConfig {
            max_active_sessions: 1,
        });
        {
            let _slot = gate.try_acquire().unwrap();
            assert!(gate.try_acquire().is_err());
        }
        assert!(gate.try_acquire().is_ok());
    }

    #[test]
    fn unlimited_mode_never_rejects() {
        let gate = BackpressureGate::new(BackpressureConfig {
            max_active_sessions: 0,
        });
        for _ in 0..1000 {
            assert!(gate.try_acquire().is_ok());
        }
    }

    #[test]
    fn is_at_capacity_reflects_state() {
        let gate = BackpressureGate::new(BackpressureConfig {
            max_active_sessions: 2,
        });
        assert!(!gate.is_at_capacity());
        let _s1 = gate.try_acquire().unwrap();
        assert!(!gate.is_at_capacity());
        let _s2 = gate.try_acquire().unwrap();
        assert!(gate.is_at_capacity());
    }

    #[test]
    fn unlimited_is_never_at_capacity() {
        let gate = BackpressureGate::new(BackpressureConfig {
            max_active_sessions: 0,
        });
        assert!(!gate.is_at_capacity());
    }

    #[test]
    fn slot_release_on_drop() {
        let gate = BackpressureGate::new(BackpressureConfig {
            max_active_sessions: 1,
        });
        {
            let _slot = gate.try_acquire().unwrap();
            assert_eq!(gate.active_count(), 1);
        }
        assert_eq!(gate.active_count(), 0);
    }

    #[test]
    fn concurrent_acquires_respect_limit() {
        use std::sync::Arc;
        use std::thread;

        let gate = Arc::new(BackpressureGate::new(BackpressureConfig {
            max_active_sessions: 3,
        }));
        let mut handles = Vec::new();
        let success_count = Arc::new(AtomicUsize::new(0));

        for _ in 0..10 {
            let gate = Arc::clone(&gate);
            let counter = Arc::clone(&success_count);
            handles.push(thread::spawn(move || {
                if let Ok(_slot) = gate.try_acquire() {
                    counter.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(std::time::Duration::from_millis(10));
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(success_count.load(Ordering::SeqCst), 3);
    }
}
