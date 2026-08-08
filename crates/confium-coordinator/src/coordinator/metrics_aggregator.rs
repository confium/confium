//! Multi-coordinator metrics aggregator.

use serde::{Deserialize, Serialize};

/// Metrics from a single coordinator instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceMetrics {
    pub instance_id: String,
    pub active_sessions: u64,
    pub total_created: u64,
    pub total_completed: u64,
    pub total_expired: u64,
    pub registered_signers: u64,
    pub aggregations_attempted: u64,
    pub aggregations_failed: u64,
}

/// Aggregated metrics across multiple coordinator instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub instance_count: usize,
    pub total_active_sessions: u64,
    pub total_created: u64,
    pub total_completed: u64,
    pub total_expired: u64,
    pub total_signers: u64,
    pub total_aggregations: u64,
    pub total_failures: u64,
    pub overall_success_rate: f64,
    pub avg_sessions_per_instance: f64,
    pub max_active_sessions: u64,
}

/// Aggregate metrics from multiple coordinator instances.
pub fn aggregate(instances: &[InstanceMetrics]) -> AggregatedMetrics {
    let count = instances.len() as u64;
    if count == 0 {
        return AggregatedMetrics {
            instance_count: 0,
            total_active_sessions: 0,
            total_created: 0,
            total_completed: 0,
            total_expired: 0,
            total_signers: 0,
            total_aggregations: 0,
            total_failures: 0,
            overall_success_rate: 1.0,
            avg_sessions_per_instance: 0.0,
            max_active_sessions: 0,
        };
    }

    let total_active: u64 = instances.iter().map(|i| i.active_sessions).sum();
    let total_created: u64 = instances.iter().map(|i| i.total_created).sum();
    let total_completed: u64 = instances.iter().map(|i| i.total_completed).sum();
    let total_expired: u64 = instances.iter().map(|i| i.total_expired).sum();
    let total_signers: u64 = instances.iter().map(|i| i.registered_signers).sum();
    let total_agg: u64 = instances.iter().map(|i| i.aggregations_attempted).sum();
    let total_fail: u64 = instances.iter().map(|i| i.aggregations_failed).sum();
    let max_active: u64 = instances
        .iter()
        .map(|i| i.active_sessions)
        .max()
        .unwrap_or(0);
    let success_rate = if total_agg > 0 {
        1.0 - (total_fail as f64 / total_agg as f64)
    } else {
        1.0
    };

    AggregatedMetrics {
        instance_count: instances.len(),
        total_active_sessions: total_active,
        total_created,
        total_completed,
        total_expired,
        total_signers,
        total_aggregations: total_agg,
        total_failures: total_fail,
        overall_success_rate: success_rate,
        avg_sessions_per_instance: total_active as f64 / count as f64,
        max_active_sessions: max_active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instance(id: &str, active: u64, created: u64) -> InstanceMetrics {
        InstanceMetrics {
            instance_id: id.into(),
            active_sessions: active,
            total_created: created,
            total_completed: created / 2,
            total_expired: 0,
            registered_signers: 3,
            aggregations_attempted: 100,
            aggregations_failed: 5,
        }
    }

    #[test]
    fn empty_instances() {
        let agg = aggregate(&[]);
        assert_eq!(agg.instance_count, 0);
        assert_eq!(agg.total_active_sessions, 0);
    }

    #[test]
    fn single_instance() {
        let agg = aggregate(&[make_instance("a", 5, 10)]);
        assert_eq!(agg.instance_count, 1);
        assert_eq!(agg.total_active_sessions, 5);
        assert_eq!(agg.total_created, 10);
    }

    #[test]
    fn sums_across_instances() {
        let agg = aggregate(&[make_instance("a", 5, 10), make_instance("b", 3, 20)]);
        assert_eq!(agg.total_active_sessions, 8);
        assert_eq!(agg.total_created, 30);
        assert_eq!(agg.total_signers, 6);
    }

    #[test]
    fn success_rate_computed() {
        let agg = aggregate(&[make_instance("a", 0, 0)]);
        assert!((agg.overall_success_rate - 0.95).abs() < 0.001);
    }

    #[test]
    fn avg_sessions() {
        let agg = aggregate(&[make_instance("a", 4, 0), make_instance("b", 6, 0)]);
        assert!((agg.avg_sessions_per_instance - 5.0).abs() < 0.001);
    }

    #[test]
    fn max_active_sessions() {
        let agg = aggregate(&[
            make_instance("a", 3, 0),
            make_instance("b", 7, 0),
            make_instance("c", 5, 0),
        ]);
        assert_eq!(agg.max_active_sessions, 7);
    }

    #[test]
    fn serializes() {
        let agg = aggregate(&[make_instance("a", 1, 1)]);
        let json = serde_json::to_string(&agg).unwrap();
        assert!(json.contains("instance_count"));
    }
}
