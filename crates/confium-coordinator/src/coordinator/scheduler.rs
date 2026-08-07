//! Share rotation scheduler — triggers periodic Herzberg refresh.
//!
//! Proactive share refresh rotates shares without changing the joint
//! public key, protecting against slow-share-compromise adversaries.
//! The scheduler runs in a background thread and periodically invokes
//! the refresh callback.

use chrono::{DateTime, Duration, Utc};
use std::sync::{Arc, Mutex};
use std::thread;

/// Configuration for the rotation scheduler.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Human-readable name for this rotation schedule.
    pub name: String,
    /// Time between refresh triggers.
    pub interval: Duration,
    /// Next scheduled run time.
    pub next_run: DateTime<Utc>,
    /// Whether the scheduler is paused.
    pub paused: bool,
}

impl RotationConfig {
    /// Create a new schedule that runs every `interval`, starting now.
    pub fn every(name: &str, interval: Duration) -> Self {
        Self {
            name: name.into(),
            interval,
            next_run: Utc::now() + interval,
            paused: false,
        }
    }

    /// Pause the scheduler (it will skip triggers until resumed).
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume the scheduler.
    pub fn resume(&mut self) {
        self.paused = false;
        self.next_run = Utc::now() + self.interval;
    }
}

/// A refresh trigger callback. The scheduler calls this when it's
/// time to rotate shares. The callback receives the schedule name.
pub type RefreshCallback = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// The rotation scheduler. Runs in a background thread, periodically
/// triggering the refresh callback.
pub struct RotationScheduler {
    config: Arc<Mutex<RotationConfig>>,
    callback: RefreshCallback,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl RotationScheduler {
    /// Create a new scheduler with the given config and callback.
    pub fn new(config: RotationConfig, callback: RefreshCallback) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            callback,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get a handle to the config for inspection or modification.
    pub fn config_handle(&self) -> Arc<Mutex<RotationConfig>> {
        Arc::clone(&self.config)
    }

    /// Start the scheduler in a background thread.
    pub fn start(&self) {
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);
        let config = Arc::clone(&self.config);
        let callback = Arc::clone(&self.callback);
        let running = Arc::clone(&self.running);

        thread::spawn(move || {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                let should_run = {
                    let cfg = config.lock().unwrap();
                    !cfg.paused && Utc::now() >= cfg.next_run
                };

                if should_run {
                    let name = {
                        let cfg = config.lock().unwrap();
                        cfg.name.clone()
                    };
                    match callback(&name) {
                        Ok(()) => tracing::info!(schedule = %name, "refresh completed"),
                        Err(e) => tracing::error!(schedule = %name, error = %e, "refresh failed"),
                    }
                    let mut cfg = config.lock().unwrap();
                    cfg.next_run = Utc::now() + cfg.interval;
                }

                thread::sleep(std::time::Duration::from_secs(1));
            }
        });
    }

    /// Stop the scheduler.
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Trigger a manual refresh immediately (bypasses the schedule).
    pub fn trigger_now(&self) -> Result<(), String> {
        let name = self.config.lock().unwrap().name.clone();
        (self.callback)(&name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn config_every_sets_interval() {
        let config = RotationConfig::every("hourly", Duration::hours(1));
        assert_eq!(config.name, "hourly");
        assert_eq!(config.interval, Duration::hours(1));
        assert!(!config.paused);
    }

    #[test]
    fn pause_prevents_and_resume_reenables() {
        let mut config = RotationConfig::every("test", Duration::minutes(5));
        config.pause();
        assert!(config.paused);
        config.resume();
        assert!(!config.paused);
    }

    #[test]
    fn trigger_now_invokes_callback() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);
        let callback: RefreshCallback = Arc::new(move |_name| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let config = RotationConfig::every("test", Duration::hours(24));
        let scheduler = RotationScheduler::new(config, callback);
        scheduler.trigger_now().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn trigger_now_propagates_error() {
        let callback: RefreshCallback = Arc::new(|_| Err("simulated failure".into()));
        let config = RotationConfig::every("test", Duration::hours(24));
        let scheduler = RotationScheduler::new(config, callback);
        assert!(scheduler.trigger_now().is_err());
    }

    #[test]
    fn config_handle_allows_modification() {
        let config = RotationConfig::every("test", Duration::hours(1));
        let scheduler = RotationScheduler::new(config, Arc::new(|_| Ok(())));
        let handle = scheduler.config_handle();
        {
            let mut cfg = handle.lock().unwrap();
            cfg.pause();
        }
        let cfg = handle.lock().unwrap();
        assert!(cfg.paused);
    }
}
