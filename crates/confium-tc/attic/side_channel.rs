//! Side-channel timing test framework.
//!
//! Provides utilities for measuring operation durations and detecting
//! timing-based information leakage. Used to verify constant-time
//! guarantees of cryptographic operations.

use std::time::{Duration, Instant};

/// A single timing measurement.
#[derive(Debug, Clone)]
pub struct TimingSample {
    pub label: String,
    pub duration: Duration,
}

/// Collect timing samples for an operation.
pub fn measure<F: FnOnce()>(label: &str, f: F) -> TimingSample {
    let start = Instant::now();
    f();
    let duration = start.elapsed();
    TimingSample {
        label: label.into(),
        duration,
    }
}

/// Collect N timing samples for an operation.
pub fn measure_n<F: Fn()>(label: &str, n: usize, f: F) -> Vec<TimingSample> {
    (0..n)
        .map(|_| {
            let start = Instant::now();
            f();
            TimingSample {
                label: label.into(),
                duration: start.elapsed(),
            }
        })
        .collect()
}

/// Statistics over a set of timing samples.
#[derive(Debug, Clone)]
pub struct TimingStats {
    pub count: usize,
    pub min: Duration,
    pub max: Duration,
    pub mean: Duration,
    pub median: Duration,
    pub stddev: Duration,
}

/// Compute statistics over timing samples.
pub fn stats(samples: &[TimingSample]) -> TimingStats {
    if samples.is_empty() {
        return TimingStats {
            count: 0,
            min: Duration::ZERO,
            max: Duration::ZERO,
            mean: Duration::ZERO,
            median: Duration::ZERO,
            stddev: Duration::ZERO,
        };
    }
    let durations: Vec<Duration> = samples.iter().map(|s| s.duration).collect();
    let min = *durations.iter().min().unwrap();
    let max = *durations.iter().max().unwrap();
    let total: Duration = durations.iter().sum();
    let mean = total / samples.len() as u32;

    let mut sorted = durations.clone();
    sorted.sort();
    let median = sorted[sorted.len() / 2];

    let variance: f64 = durations
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean.as_nanos() as f64;
            diff * diff
        })
        .sum::<f64>()
        / samples.len() as f64;
    let stddev = Duration::from_nanos(variance.sqrt() as u64);

    TimingStats {
        count: samples.len(),
        min,
        max,
        mean,
        median,
        stddev,
    }
}

/// Compare timing distributions between two groups. Returns the
/// ratio of max/min mean. A ratio near 1.0 suggests constant-time;
/// a large ratio suggests timing leakage.
pub fn timing_ratio(group_a: &[TimingSample], group_b: &[TimingSample]) -> f64 {
    let stats_a = stats(group_a);
    let stats_b = stats(group_b);
    let mean_a = stats_a.mean.as_nanos() as f64;
    let mean_b = stats_b.mean.as_nanos() as f64;
    if mean_a == 0.0 || mean_b == 0.0 {
        return 1.0;
    }
    let (larger, smaller) = if mean_a > mean_b {
        (mean_a, mean_b)
    } else {
        (mean_b, mean_a)
    };
    larger / smaller
}

/// Check if two groups have consistent timing (ratio < threshold).
pub fn is_constant_time(group_a: &[TimingSample], group_b: &[TimingSample], threshold: f64) -> bool {
    timing_ratio(group_a, group_b) < threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn measure_returns_duration() {
        let sample = measure("test", || {
            thread::sleep(Duration::from_micros(100));
        });
        assert!(sample.duration >= Duration::from_micros(90));
    }

    #[test]
    fn measure_n_returns_multiple() {
        let samples = measure_n("test", 5, || {});
        assert_eq!(samples.len(), 5);
        assert!(samples.iter().all(|s| s.label == "test"));
    }

    #[test]
    fn stats_empty_returns_zero() {
        let s = stats(&[]);
        assert_eq!(s.count, 0);
    }

    #[test]
    fn stats_computes_min_max() {
        let samples = vec![
            TimingSample { label: "x".into(), duration: Duration::from_nanos(100) },
            TimingSample { label: "x".into(), duration: Duration::from_nanos(300) },
            TimingSample { label: "x".into(), duration: Duration::from_nanos(200) },
        ];
        let s = stats(&samples);
        assert_eq!(s.min, Duration::from_nanos(100));
        assert_eq!(s.max, Duration::from_nanos(300));
    }

    #[test]
    fn stats_computes_mean() {
        let samples = vec![
            TimingSample { label: "x".into(), duration: Duration::from_nanos(100) },
            TimingSample { label: "x".into(), duration: Duration::from_nanos(200) },
            TimingSample { label: "x".into(), duration: Duration::from_nanos(300) },
        ];
        let s = stats(&samples);
        assert_eq!(s.mean, Duration::from_nanos(200));
    }

    #[test]
    fn stats_computes_median() {
        let samples = vec![
            TimingSample { label: "x".into(), duration: Duration::from_nanos(100) },
            TimingSample { label: "x".into(), duration: Duration::from_nanos(200) },
            TimingSample { label: "x".into(), duration: Duration::from_nanos(300) },
            TimingSample { label: "x".into(), duration: Duration::from_nanos(400) },
            TimingSample { label: "x".into(), duration: Duration::from_nanos(500) },
        ];
        let s = stats(&samples);
        assert_eq!(s.median, Duration::from_nanos(300));
    }

    #[test]
    fn timing_ratio_equal_groups() {
        let a = vec![TimingSample { label: "a".into(), duration: Duration::from_nanos(100) }];
        let b = vec![TimingSample { label: "b".into(), duration: Duration::from_nanos(100) }];
        assert!((timing_ratio(&a, &b) - 1.0).abs() < 0.01);
    }

    #[test]
    fn timing_ratio_different_groups() {
        let a = vec![TimingSample { label: "a".into(), duration: Duration::from_nanos(100) }];
        let b = vec![TimingSample { label: "b".into(), duration: Duration::from_nanos(200) }];
        assert!((timing_ratio(&a, &b) - 2.0).abs() < 0.01);
    }

    #[test]
    fn is_constant_time_passes_for_equal() {
        let a = vec![TimingSample { label: "a".into(), duration: Duration::from_nanos(100) }];
        let b = vec![TimingSample { label: "b".into(), duration: Duration::from_nanos(105) }];
        assert!(is_constant_time(&a, &b, 1.5));
    }

    #[test]
    fn is_constant_time_fails_for_different() {
        let a = vec![TimingSample { label: "a".into(), duration: Duration::from_nanos(100) }];
        let b = vec![TimingSample { label: "b".into(), duration: Duration::from_nanos(500) }];
        assert!(!is_constant_time(&a, &b, 1.5));
    }
}
