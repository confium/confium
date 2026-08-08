//! Performance baseline manager — save/load/compare Criterion baselines.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A performance measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub mean_ns: f64,
    pub median_ns: f64,
    pub stddev_ns: f64,
    pub samples: usize,
}

/// A baseline — a set of benchmark results at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub results: Vec<BenchmarkResult>,
}

/// Comparison result between a measurement and a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub name: String,
    pub baseline_ns: f64,
    pub current_ns: f64,
    pub change_pct: f64,
    pub regression: bool,
}

/// Regression threshold (percentage above baseline that counts as regression).
const REGRESSION_THRESHOLD_PCT: f64 = 10.0;

/// Compare current results against a baseline.
pub fn compare(current: &[BenchmarkResult], baseline: &Baseline) -> Vec<Comparison> {
    let baseline_map: HashMap<&str, &BenchmarkResult> = baseline
        .results
        .iter()
        .map(|r| (r.name.as_str(), r))
        .collect();

    current
        .iter()
        .filter_map(|c| {
            let base = baseline_map.get(c.name.as_str())?;
            let change_pct = ((c.mean_ns - base.mean_ns) / base.mean_ns) * 100.0;
            Some(Comparison {
                name: c.name.clone(),
                baseline_ns: base.mean_ns,
                current_ns: c.mean_ns,
                change_pct,
                regression: change_pct > REGRESSION_THRESHOLD_PCT,
            })
        })
        .collect()
}

/// Save a baseline to a JSON file.
pub fn save_baseline(baseline: &Baseline, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(baseline)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Load a baseline from a JSON file.
pub fn load_baseline(path: &Path) -> std::io::Result<Baseline> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Create a baseline from benchmark results.
pub fn create_baseline(name: &str, results: Vec<BenchmarkResult>) -> Baseline {
    Baseline {
        name: name.into(),
        created_at: chrono::Utc::now(),
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(name: &str, mean_ns: f64) -> BenchmarkResult {
        BenchmarkResult {
            name: name.into(),
            mean_ns,
            median_ns: mean_ns,
            stddev_ns: 10.0,
            samples: 100,
        }
    }

    #[test]
    fn create_baseline_works() {
        let baseline = create_baseline("v1", vec![make_result("bench_a", 1000.0)]);
        assert_eq!(baseline.name, "v1");
        assert_eq!(baseline.results.len(), 1);
    }

    #[test]
    fn compare_no_change() {
        let baseline = create_baseline("v1", vec![make_result("bench_a", 1000.0)]);
        let current = vec![make_result("bench_a", 1000.0)];
        let comparisons = compare(&current, &baseline);
        assert_eq!(comparisons.len(), 1);
        assert!(!comparisons[0].regression);
    }

    #[test]
    fn compare_detects_regression() {
        let baseline = create_baseline("v1", vec![make_result("bench_a", 1000.0)]);
        let current = vec![make_result("bench_a", 1200.0)];
        let comparisons = compare(&current, &baseline);
        assert_eq!(comparisons[0].change_pct, 20.0);
        assert!(comparisons[0].regression);
    }

    #[test]
    fn compare_improvement_not_regression() {
        let baseline = create_baseline("v1", vec![make_result("bench_a", 1000.0)]);
        let current = vec![make_result("bench_a", 800.0)];
        let comparisons = compare(&current, &baseline);
        assert!(!comparisons[0].regression);
    }

    #[test]
    fn compare_handles_missing_benchmarks() {
        let baseline = create_baseline("v1", vec![make_result("a", 1.0)]);
        let current = vec![make_result("b", 2.0)];
        let comparisons = compare(&current, &baseline);
        assert!(comparisons.is_empty());
    }

    #[test]
    fn save_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("baseline.json");
        let baseline = create_baseline("test", vec![make_result("x", 42.0)]);
        save_baseline(&baseline, &path).unwrap();
        let loaded = load_baseline(&path).unwrap();
        assert_eq!(loaded.name, "test");
        assert_eq!(loaded.results[0].mean_ns, 42.0);
    }

    #[test]
    fn regression_threshold_10pct() {
        let baseline = create_baseline("v1", vec![make_result("a", 100.0)]);
        let current = vec![make_result("a", 109.0)]; // 9% slower
        let comparisons = compare(&current, &baseline);
        assert!(!comparisons[0].regression); // under 10%
    }

    #[test]
    fn multiple_benchmarks_compared() {
        let baseline =
            create_baseline("v1", vec![make_result("a", 100.0), make_result("b", 200.0)]);
        let current = vec![
            make_result("a", 150.0), // 50% regression
            make_result("b", 190.0), // 5% improvement
        ];
        let comparisons = compare(&current, &baseline);
        assert_eq!(comparisons.len(), 2);
        assert!(comparisons[0].regression);
        assert!(!comparisons[1].regression);
    }
}
