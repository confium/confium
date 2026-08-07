//! Coordinator capability advertisement — feature flags.

use serde::{Deserialize, Serialize};

/// Capabilities a coordinator supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorCapabilities {
    /// Supported threshold schemes.
    pub schemes: Vec<String>,
    /// Supported algorithms.
    pub algorithms: Vec<String>,
    /// Maximum threshold the coordinator can handle.
    pub max_threshold: u32,
    /// Maximum party count.
    pub max_party_count: u32,
    /// Whether batch signing is supported.
    pub supports_batch: bool,
    /// Whether idempotency keys are supported.
    pub supports_idempotency: bool,
    /// Whether backpressure enforcement is active.
    pub supports_backpressure: bool,
    /// Protocol version.
    pub protocol_version: u32,
}

impl Default for CoordinatorCapabilities {
    fn default() -> Self {
        Self {
            schemes: vec!["CMP20".into(), "FROST-P256".into(), "GG18".into()],
            algorithms: vec!["ECDSA-P256".into(), "Ed25519".into()],
            max_threshold: 32,
            max_party_count: 64,
            supports_batch: true,
            supports_idempotency: true,
            supports_backpressure: true,
            protocol_version: 1,
        }
    }
}

impl CoordinatorCapabilities {
    /// Check if a scheme is supported.
    pub fn supports_scheme(&self, scheme: &str) -> bool {
        self.schemes.iter().any(|s| s == scheme)
    }

    /// Check if an algorithm is supported.
    pub fn supports_algorithm(&self, alg: &str) -> bool {
        self.algorithms.iter().any(|a| a == alg)
    }

    /// Check if a threshold/party combination is within limits.
    pub fn supports_config(&self, threshold: u32, party_count: u32) -> bool {
        threshold <= self.max_threshold && party_count <= self.max_party_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_schemes() {
        let caps = CoordinatorCapabilities::default();
        assert!(caps.supports_scheme("CMP20"));
        assert!(!caps.supports_scheme("UnknownScheme"));
    }

    #[test]
    fn algorithm_check() {
        let caps = CoordinatorCapabilities::default();
        assert!(caps.supports_algorithm("Ed25519"));
        assert!(!caps.supports_algorithm("RSA"));
    }

    #[test]
    fn config_within_limits() {
        let caps = CoordinatorCapabilities::default();
        assert!(caps.supports_config(5, 10));
        assert!(!caps.supports_config(100, 10));
        assert!(!caps.supports_config(5, 100));
    }

    #[test]
    fn serializes() {
        let caps = CoordinatorCapabilities::default();
        let json = serde_json::to_string(&caps).unwrap();
        assert!(json.contains("schemes"));
        assert!(json.contains("supports_batch"));
    }
}
