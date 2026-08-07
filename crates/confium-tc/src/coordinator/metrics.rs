//! Coordinator metrics — Prometheus-compatible counters and gauges.
//!
//! Tracks session lifecycle events and operational health. Exposed via
//! the TCP protocol (`MetricsQuery` / `MetricsResponse`) and renderable
//! in Prometheus text format.

use std::sync::atomic::{AtomicU64, Ordering};

/// Coordinator-level metrics. All fields are atomic for thread-safe
/// increments from the coordinator's connection handler threads.
#[derive(Debug, Default)]
pub struct CoordinatorMetrics {
    /// Total sessions created since coordinator start.
    sessions_created: AtomicU64,
    /// Total sessions completed (aggregated successfully).
    sessions_completed: AtomicU64,
    /// Total sessions expired (unlock window elapsed).
    sessions_expired: AtomicU64,
    /// Total sessions aborted.
    sessions_aborted: AtomicU64,
    /// Total signature aggregations attempted.
    aggregations_attempted: AtomicU64,
    /// Total signature aggregations that failed.
    aggregations_failed: AtomicU64,
    /// Currently active sessions.
    active_sessions: AtomicU64,
    /// Currently registered signers.
    registered_signers: AtomicU64,
    /// Total bytes of messages processed.
    bytes_processed: AtomicU64,
}

impl CoordinatorMetrics {
    /// Record a session creation.
    pub fn record_session_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a session completion.
    pub fn record_session_completed(&self) {
        self.sessions_completed.fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a session expiration.
    pub fn record_session_expired(&self) {
        self.sessions_expired.fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a session abort.
    pub fn record_session_aborted(&self) {
        self.sessions_aborted.fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record an aggregation attempt.
    pub fn record_aggregation_attempted(&self) {
        self.aggregations_attempted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed aggregation.
    pub fn record_aggregation_failed(&self) {
        self.aggregations_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the registered signer count.
    pub fn set_registered_signers(&self, count: u64) {
        self.registered_signers.store(count, Ordering::Relaxed);
    }

    /// Record bytes processed.
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Render metrics in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP confium_sessions_created_total Total sessions created.\n");
        out.push_str("# TYPE confium_sessions_created_total counter\n");
        out.push_str(&format!(
            "confium_sessions_created_total {}\n",
            self.sessions_created.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP confium_sessions_completed_total Total sessions completed.\n");
        out.push_str("# TYPE confium_sessions_completed_total counter\n");
        out.push_str(&format!(
            "confium_sessions_completed_total {}\n",
            self.sessions_completed.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP confium_sessions_expired_total Total sessions expired.\n");
        out.push_str("# TYPE confium_sessions_expired_total counter\n");
        out.push_str(&format!(
            "confium_sessions_expired_total {}\n",
            self.sessions_expired.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP confium_sessions_aborted_total Total sessions aborted.\n");
        out.push_str("# TYPE confium_sessions_aborted_total counter\n");
        out.push_str(&format!(
            "confium_sessions_aborted_total {}\n",
            self.sessions_aborted.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP confium_aggregations_attempted_total Total aggregation attempts.\n");
        out.push_str("# TYPE confium_aggregations_attempted_total counter\n");
        out.push_str(&format!(
            "confium_aggregations_attempted_total {}\n",
            self.aggregations_attempted.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP confium_aggregations_failed_total Total failed aggregations.\n");
        out.push_str("# TYPE confium_aggregations_failed_total counter\n");
        out.push_str(&format!(
            "confium_aggregations_failed_total {}\n",
            self.aggregations_failed.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP confium_active_sessions Currently active sessions.\n");
        out.push_str("# TYPE confium_active_sessions gauge\n");
        out.push_str(&format!(
            "confium_active_sessions {}\n",
            self.active_sessions.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP confium_registered_signers Currently registered signers.\n");
        out.push_str("# TYPE confium_registered_signers gauge\n");
        out.push_str(&format!(
            "confium_registered_signers {}\n",
            self.registered_signers.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP confium_bytes_processed_total Total bytes processed.\n");
        out.push_str("# TYPE confium_bytes_processed_total counter\n");
        out.push_str(&format!(
            "confium_bytes_processed_total {}\n",
            self.bytes_processed.load(Ordering::Relaxed)
        ));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_metrics_render_correctly() {
        let m = CoordinatorMetrics::default();
        let text = m.render_prometheus();
        assert!(text.contains("confium_sessions_created_total 0"));
        assert!(text.contains("confium_active_sessions 0"));
    }

    #[test]
    fn session_lifecycle_increments() {
        let m = CoordinatorMetrics::default();
        m.record_session_created();
        m.record_session_created();
        m.record_session_completed();
        m.record_session_expired();

        let text = m.render_prometheus();
        assert!(text.contains("confium_sessions_created_total 2"));
        assert!(text.contains("confium_sessions_completed_total 1"));
        assert!(text.contains("confium_sessions_expired_total 1"));
        assert!(text.contains("confium_active_sessions 0"));
    }

    #[test]
    fn aggregation_metrics() {
        let m = CoordinatorMetrics::default();
        m.record_aggregation_attempted();
        m.record_aggregation_attempted();
        m.record_aggregation_failed();

        let text = m.render_prometheus();
        assert!(text.contains("confium_aggregations_attempted_total 2"));
        assert!(text.contains("confium_aggregations_failed_total 1"));
    }

    #[test]
    fn prometheus_format_has_help_and_type() {
        let m = CoordinatorMetrics::default();
        let text = m.render_prometheus();
        assert!(text.contains("# HELP"));
        assert!(text.contains("# TYPE"));
        assert!(text.contains("counter"));
        assert!(text.contains("gauge"));
    }

    #[test]
    fn registered_signers_gauge() {
        let m = CoordinatorMetrics::default();
        m.set_registered_signers(5);
        let text = m.render_prometheus();
        assert!(text.contains("confium_registered_signers 5"));
    }

    #[test]
    fn bytes_processed_accumulates() {
        let m = CoordinatorMetrics::default();
        m.record_bytes(100);
        m.record_bytes(250);
        let text = m.render_prometheus();
        assert!(text.contains("confium_bytes_processed_total 350"));
    }
}
