//! Coordinator diagnostics — self-health report generation.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// A comprehensive diagnostics report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    /// Build version.
    pub version: String,
    /// When the coordinator started.
    pub started_at: DateTime<Utc>,
    /// When this report was generated.
    pub generated_at: DateTime<Utc>,
    /// Uptime in seconds.
    pub uptime_seconds: i64,
    /// Active session count.
    pub active_sessions: usize,
    /// Total sessions created.
    pub total_sessions_created: u64,
    /// Total sessions completed.
    pub total_sessions_completed: u64,
    /// Total sessions expired.
    pub total_sessions_expired: u64,
    /// Registered signer count.
    pub registered_signers: usize,
    /// Total aggregations attempted.
    pub aggregations_attempted: u64,
    /// Total aggregations failed.
    pub aggregations_failed: u64,
    /// Aggregation success rate (0.0–1.0).
    pub success_rate: f64,
    /// Memory usage estimate (bytes).
    pub memory_usage_bytes: u64,
    /// Any warnings.
    pub warnings: Vec<String>,
}

impl DiagnosticsReport {
    /// Generate a report from the current coordinator state.
    pub fn generate(
        version: &str,
        started_at: DateTime<Utc>,
        active_sessions: usize,
        total_created: u64,
        total_completed: u64,
        total_expired: u64,
        registered_signers: usize,
        aggregations_attempted: u64,
        aggregations_failed: u64,
    ) -> Self {
        let now = Utc::now();
        let uptime = now - started_at;
        let success_rate = if aggregations_attempted > 0 {
            1.0 - (aggregations_failed as f64 / aggregations_attempted as f64)
        } else {
            1.0
        };

        let mut warnings = Vec::new();
        if success_rate < 0.95 {
            warnings.push(format!(
                "Success rate {:.1}% is below 95%",
                success_rate * 100.0
            ));
        }
        if active_sessions > 50 {
            warnings.push(format!("{active_sessions} active sessions (high)"));
        }
        if registered_signers == 0 && total_created > 0 {
            warnings.push("No registered signers but sessions exist".into());
        }
        if uptime > Duration::zero() && total_created > 0 {
            let sessions_per_hour = total_created as f64 / (uptime.num_seconds() as f64 / 3600.0);
            if sessions_per_hour > 1000.0 {
                warnings.push(format!(
                    "{:.0} sessions/hour (high load)",
                    sessions_per_hour
                ));
            }
        }

        Self {
            version: version.into(),
            started_at,
            generated_at: now,
            uptime_seconds: uptime.num_seconds(),
            active_sessions,
            total_sessions_created: total_created,
            total_sessions_completed: total_completed,
            total_sessions_expired: total_expired,
            registered_signers,
            aggregations_attempted,
            aggregations_failed,
            success_rate,
            memory_usage_bytes: estimate_memory_usage(active_sessions, registered_signers),
            warnings,
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Is the coordinator healthy (no warnings)?
    pub fn is_healthy(&self) -> bool {
        self.warnings.is_empty() && self.success_rate >= 0.95
    }
}

fn estimate_memory_usage(active_sessions: usize, registered_signers: usize) -> u64 {
    // Rough estimate: each session ~4KB, each signer connection ~2KB
    (active_sessions as u64 * 4096) + (registered_signers as u64 * 2048) + 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report(
        active: usize,
        created: u64,
        completed: u64,
        signers: usize,
        agg_attempted: u64,
        agg_failed: u64,
    ) -> DiagnosticsReport {
        DiagnosticsReport::generate(
            "0.3.0",
            Utc::now() - Duration::minutes(10),
            active,
            created,
            completed,
            0,
            signers,
            agg_attempted,
            agg_failed,
        )
    }

    #[test]
    fn healthy_report_has_no_warnings() {
        let report = make_report(5, 10, 9, 3, 10, 0);
        assert!(report.warnings.is_empty());
        assert!(report.is_healthy());
    }

    #[test]
    fn low_success_rate_warns() {
        let report = make_report(5, 10, 5, 3, 10, 2);
        assert!(report.warnings.iter().any(|w| w.contains("Success rate")));
    }

    #[test]
    fn many_sessions_warns() {
        let report = make_report(60, 100, 40, 5, 100, 5);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("active sessions"))
        );
    }

    #[test]
    fn no_signers_with_sessions_warns() {
        let report = make_report(5, 10, 5, 0, 10, 0);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("No registered signers"))
        );
    }

    #[test]
    fn uptime_positive() {
        let report = make_report(0, 0, 0, 0, 0, 0);
        assert!(report.uptime_seconds > 0);
    }

    #[test]
    fn success_rate_zero_when_no_aggregations() {
        let report = make_report(0, 0, 0, 0, 0, 0);
        assert_eq!(report.success_rate, 1.0);
    }

    #[test]
    fn success_rate_computed() {
        let report = make_report(0, 0, 0, 0, 100, 10);
        assert!((report.success_rate - 0.9).abs() < 0.001);
    }

    #[test]
    fn json_serialization_works() {
        let report = make_report(1, 1, 1, 1, 1, 0);
        let json = report.to_json().unwrap();
        assert!(json.contains("version"));
        assert!(json.contains("uptime_seconds"));
    }

    #[test]
    fn memory_usage_estimated() {
        let report = make_report(10, 0, 0, 5, 0, 0);
        assert!(report.memory_usage_bytes > 1_000_000);
    }

    #[test]
    fn version_included() {
        let report = make_report(0, 0, 0, 0, 0, 0);
        assert_eq!(report.version, "0.3.0");
    }
}
