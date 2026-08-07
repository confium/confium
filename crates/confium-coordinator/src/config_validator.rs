//! Configuration validator — pre-flight checks for coordinator/daemon configs.

use serde::{Deserialize, Serialize};

/// Result of configuration validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// True if all checks passed.
    pub valid: bool,
    /// List of issues found (empty if valid).
    pub issues: Vec<ConfigIssue>,
}

/// A single configuration issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigIssue {
    /// Which field has the problem.
    pub field: String,
    /// What's wrong.
    pub message: String,
    /// Suggested fix.
    pub suggestion: String,
    /// Severity: "error" (blocks startup) or "warning".
    pub severity: String,
}

impl ValidationResult {
    /// Check if there are any errors (not just warnings).
    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|i| i.severity == "error")
    }

    /// Only error issues.
    pub fn errors(&self) -> impl Iterator<Item = &ConfigIssue> {
        self.issues.iter().filter(|i| i.severity == "error")
    }
}

/// Validate a coordinator configuration.
pub fn validate_coordinator_config(
    addr: &str,
    max_sessions: usize,
    session_timeout_secs: u64,
) -> ValidationResult {
    let mut issues = Vec::new();

    if addr.is_empty() {
        issues.push(ConfigIssue {
            field: "addr".into(),
            message: "address is empty".into(),
            suggestion: "set to e.g. '0.0.0.0:18432'".into(),
            severity: "error".into(),
        });
    } else if !addr.contains(':') {
        issues.push(ConfigIssue {
            field: "addr".into(),
            message: "address missing port".into(),
            suggestion: "format: 'host:port'".into(),
            severity: "error".into(),
        });
    }

    if max_sessions == 0 {
        issues.push(ConfigIssue {
            field: "max_sessions".into(),
            message: "max_sessions is 0 (unlimited)".into(),
            suggestion: "set a positive limit for production".into(),
            severity: "warning".into(),
        });
    }

    if session_timeout_secs < 60 {
        issues.push(ConfigIssue {
            field: "session_timeout_secs".into(),
            message: "timeout < 60 seconds may be too short".into(),
            suggestion: "use at least 300 (5 min) for production".into(),
            severity: "warning".into(),
        });
    }

    ValidationResult {
        valid: !issues.iter().any(|i| i.severity == "error"),
        issues,
    }
}

/// Validate a signer daemon configuration.
pub fn validate_signer_config(
    coordinator_addr: &str,
    signer_id: &str,
    quorum_id: &str,
    share_file: &str,
) -> ValidationResult {
    let mut issues = Vec::new();

    if signer_id.is_empty() {
        issues.push(ConfigIssue {
            field: "signer_id".into(),
            message: "signer_id is empty".into(),
            suggestion: "set a unique signer identity".into(),
            severity: "error".into(),
        });
    }

    if quorum_id.is_empty() {
        issues.push(ConfigIssue {
            field: "quorum_id".into(),
            message: "quorum_id is empty".into(),
            suggestion: "set the quorum this signer belongs to".into(),
            severity: "error".into(),
        });
    }

    if coordinator_addr.is_empty() || !coordinator_addr.contains(':') {
        issues.push(ConfigIssue {
            field: "coordinator_addr".into(),
            message: "coordinator_addr is invalid".into(),
            suggestion: "format: 'host:port'".into(),
            severity: "error".into(),
        });
    }

    if share_file.is_empty() {
        issues.push(ConfigIssue {
            field: "share_file".into(),
            message: "share_file is empty".into(),
            suggestion: "set path to the share JSON file".into(),
            severity: "error".into(),
        });
    }

    ValidationResult {
        valid: !issues.iter().any(|i| i.severity == "error"),
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_coordinator_config_passes() {
        let result = validate_coordinator_config("0.0.0.0:18432", 100, 3600);
        assert!(result.valid);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn empty_addr_rejected() {
        let result = validate_coordinator_config("", 100, 3600);
        assert!(!result.valid);
        assert!(result.has_errors());
    }

    #[test]
    fn missing_port_rejected() {
        let result = validate_coordinator_config("localhost", 100, 3600);
        assert!(!result.valid);
    }

    #[test]
    fn unlimited_sessions_warns() {
        let result = validate_coordinator_config("0.0.0.0:80", 0, 3600);
        assert!(result.valid); // warning, not error
        assert!(!result.has_errors());
    }

    #[test]
    fn short_timeout_warns() {
        let result = validate_coordinator_config("0.0.0.0:80", 10, 30);
        assert!(result.valid);
        assert!(result.issues.iter().any(|i| i.field == "session_timeout_secs"));
    }

    #[test]
    fn valid_signer_config_passes() {
        let result = validate_signer_config("localhost:18432", "alice", "quorum-1", "/shares/a.json");
        assert!(result.valid);
    }

    #[test]
    fn empty_signer_id_rejected() {
        let result = validate_signer_config("localhost:18432", "", "q", "/s.json");
        assert!(!result.valid);
    }

    #[test]
    fn empty_share_file_rejected() {
        let result = validate_signer_config("localhost:18432", "alice", "q", "");
        assert!(!result.valid);
    }

    #[test]
    fn issue_has_suggestion() {
        let result = validate_coordinator_config("", 10, 3600);
        for issue in &result.issues {
            assert!(!issue.suggestion.is_empty());
        }
    }

    #[test]
    fn errors_filtered_correctly() {
        let result = validate_coordinator_config("", 0, 30);
        let errors: Vec<_> = result.errors().collect();
        assert!(errors.iter().any(|e| e.severity == "error"));
        assert!(result.issues.iter().any(|i| i.severity == "warning"));
    }
}
