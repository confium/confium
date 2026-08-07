//! Chaos testing harness — random failure injection.

use rand_core::{OsRng, RngCore};
use std::collections::HashMap;

/// Failure modes to inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureMode {
    /// Signer drops the connection.
    DropConnection,
    /// Signer sends invalid data.
    InvalidData,
    /// Signer takes too long.
    Timeout,
    /// Signer sends an incorrect partial signature.
    BadSignature,
    /// No failure — control case.
    None,
}

/// Configuration for chaos testing.
#[derive(Debug, Clone)]
pub struct ChaosConfig {
    /// Probability of injecting a failure per operation.
    pub failure_rate: f64,
    /// Allowed failure modes.
    pub allowed_modes: Vec<FailureMode>,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            failure_rate: 0.1,
            allowed_modes: vec![
                FailureMode::DropConnection,
                FailureMode::InvalidData,
                FailureMode::Timeout,
                FailureMode::BadSignature,
            ],
        }
    }
}

/// Chaos tester: tracks failures injected and verifies resilience.
pub struct ChaosTester {
    config: ChaosConfig,
    injections: Vec<ChaosInjection>,
}

#[derive(Debug, Clone)]
pub struct ChaosInjection {
    pub operation: String,
    pub mode: FailureMode,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ChaosTester {
    pub fn new(config: ChaosConfig) -> Self {
        Self {
            config,
            injections: Vec::new(),
        }
    }

    /// Decide whether to inject a failure for the given operation.
    pub fn inject(&mut self, operation: &str) -> FailureMode {
        let mut rng_bytes = [0u8; 1];
        OsRng.fill_bytes(&mut rng_bytes);
        let p = rng_bytes[0] as f64 / 256.0;

        if p >= self.config.failure_rate {
            return FailureMode::None;
        }

        let mut idx_bytes = [0u8; 2];
        OsRng.fill_bytes(&mut idx_bytes);
        let idx = (u16::from_le_bytes(idx_bytes) as usize) % self.config.allowed_modes.len();
        let mode = self.config.allowed_modes[idx];
        self.injections.push(ChaosInjection {
            operation: operation.into(),
            mode,
            timestamp: chrono::Utc::now(),
        });
        mode
    }

    /// All injections recorded.
    pub fn injections(&self) -> &[ChaosInjection] {
        &self.injections
    }

    /// Count injections by mode.
    pub fn count_by_mode(&self) -> HashMap<FailureMode, usize> {
        let mut counts = HashMap::new();
        for inj in &self.injections {
            *counts.entry(inj.mode).or_insert(0) += 1;
        }
        counts
    }

    /// Number of total operations.
    pub fn total_injections(&self) -> usize {
        self.injections.len()
    }

    /// Reset injection history.
    pub fn reset(&mut self) {
        self.injections.clear();
    }
}

/// Simulate a network operation, injecting a failure if chaos decides.
pub fn simulate_operation(
    tester: &mut ChaosTester,
    operation: &str,
    success_result: &str,
) -> Result<String, String> {
    let injection = tester.inject(operation);
    match injection {
        FailureMode::None => Ok(success_result.to_string()),
        FailureMode::DropConnection => Err("connection dropped".into()),
        FailureMode::InvalidData => Err("invalid data received".into()),
        FailureMode::Timeout => Err("operation timed out".into()),
        FailureMode::BadSignature => Err("signature verification failed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_failure_rate_no_injections() {
        let config = ChaosConfig { failure_rate: 0.0, allowed_modes: vec![FailureMode::DropConnection] };
        let mut tester = ChaosTester::new(config);
        for _ in 0..100 {
            let mode = tester.inject("test");
            assert_eq!(mode, FailureMode::None);
        }
        assert_eq!(tester.total_injections(), 0);
    }

    #[test]
    fn full_failure_rate_injects() {
        let config = ChaosConfig { failure_rate: 1.0, allowed_modes: vec![FailureMode::Timeout] };
        let mut tester = ChaosTester::new(config);
        let mut non_none = 0;
        for _ in 0..100 {
            if tester.inject("test") != FailureMode::None {
                non_none += 1;
            }
        }
        assert!(non_none > 50, "expected most to inject, got {} non-none", non_none);
    }

    #[test]
    fn injections_recorded() {
        let config = ChaosConfig { failure_rate: 1.0, allowed_modes: vec![FailureMode::Timeout] };
        let mut tester = ChaosTester::new(config);
        tester.inject("test1");
        tester.inject("test2");
        assert_eq!(tester.injections().len(), 2);
    }

    #[test]
    fn count_by_mode() {
        let config = ChaosConfig { failure_rate: 1.0, allowed_modes: vec![FailureMode::DropConnection, FailureMode::Timeout] };
        let mut tester = ChaosTester::new(config);
        for _ in 0..10 { tester.inject("op"); }
        let counts = tester.count_by_mode();
        let total: usize = counts.values().sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn simulate_success_without_chaos() {
        let config = ChaosConfig { failure_rate: 0.0, allowed_modes: vec![] };
        let mut tester = ChaosTester::new(config);
        let result = simulate_operation(&mut tester, "op", "ok");
        assert!(result.is_ok());
    }

    #[test]
    fn simulate_failure_with_chaos() {
        let config = ChaosConfig { failure_rate: 1.0, allowed_modes: vec![FailureMode::DropConnection] };
        let mut tester = ChaosTester::new(config);
        let result = simulate_operation(&mut tester, "op", "ok");
        assert!(result.is_err());
    }

    #[test]
    fn reset_clears_history() {
        let config = ChaosConfig { failure_rate: 1.0, allowed_modes: vec![FailureMode::Timeout] };
        let mut tester = ChaosTester::new(config);
        tester.inject("op1");
        tester.inject("op2");
        assert_eq!(tester.total_injections(), 2);
        tester.reset();
        assert_eq!(tester.total_injections(), 0);
    }

    #[test]
    fn each_mode_unique_failure() {
        for mode in [FailureMode::DropConnection, FailureMode::InvalidData, FailureMode::Timeout, FailureMode::BadSignature] {
            let config = ChaosConfig { failure_rate: 1.0, allowed_modes: vec![mode] };
            let mut tester = ChaosTester::new(config);
            let result = simulate_operation(&mut tester, "op", "ok");
            assert!(result.is_err(), "expected error for {:?}", mode);
        }
    }
}
