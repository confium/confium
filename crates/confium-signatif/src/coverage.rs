//! Coverage reports and trust classification (SIGNATIF §14).
//!
//! The pipeline produces an **objective** [`CoverageReport`] — facts,
//! not judgements. The scheme's [`ClassificationPolicy`] maps the
//! report to a [`ClassificationLabel`] (a pure, deterministic function
//! published in the deployment manifest). The verifier's
//! [`AcceptancePolicy`] maps the label to an accept/reject decision for
//! a given decision context. Three layers, three owners.

use serde::{Deserialize, Serialize};

/// The objective verification facts collected by the pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Whether every hard check passed (format, signatures, chain,
    /// scope narrowing, conditions, revocation).
    pub hard_checks: HardCheckStatus,
    /// Whether the artifact (or its certificates) are provably included
    /// in a recognized transparency log.
    pub transparency_included: bool,
    /// Whether a time dimension attestation anchored to an external
    /// source was verified.
    pub time_anchored: bool,
    /// The trust dimensions whose attestations verified.
    pub dimensions_verified: Vec<String>,
    /// Count of independently attested dimensions.
    pub dimension_count: usize,
    /// Count of distinct roots across verified paths (cross-domain
    /// diversity).
    pub independent_roots: usize,
    /// Whether the multi-log M-of-K inclusion quorum was met.
    pub multi_log_quorum: bool,
    /// Number of valid verification paths found.
    pub paths_found: usize,
    /// Downgrade reasons accumulated from soft checks.
    pub downgrades: Vec<String>,
}

/// Hard-check outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardCheckStatus {
    /// All hard checks passed.
    Pass,
    /// A hard check failed — the pipeline short-circuits to rejected.
    Fail,
}

/// A classification label produced by a scheme's policy.
///
/// The reference stack uses: `unverified`, `basic`, `verified`,
/// `attested`, `certified`, `rejected`; schemes may define their own.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ClassificationLabel(pub String);

impl ClassificationLabel {
    /// The mandatory rejection label.
    pub const REJECTED: &'static str = "rejected";

    /// Build an arbitrary label.
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }
}

/// A scheme-defined classification policy: a pure function from the
/// coverage report to a label. The reference policy implements the
/// Annex E ladder; schemes replace it via their deployment manifest.
pub trait ClassificationPolicy {
    /// Map a coverage report to a classification label.
    fn classify(&self, report: &CoverageReport) -> ClassificationLabel;
}

/// The reference ladder from Annex E:
/// rejected → unverified → basic → verified → attested → certified.
///
/// - any hard-check failure → `rejected`
/// - no transparency, no time anchor, no person → `unverified`
/// - transparency only → `basic`
/// - transparency + time → `verified`
/// - + person dimension → `attested`
/// - + ≥2 independent roots → `certified`
#[derive(Debug, Clone, Default)]
pub struct ReferenceClassificationPolicy;

impl ClassificationPolicy for ReferenceClassificationPolicy {
    fn classify(&self, report: &CoverageReport) -> ClassificationLabel {
        if report.hard_checks == HardCheckStatus::Fail {
            return ClassificationLabel::new(ClassificationLabel::REJECTED);
        }
        if !report.transparency_included {
            return ClassificationLabel::new("unverified");
        }
        if !report.time_anchored {
            return ClassificationLabel::new("basic");
        }
        let dims: Vec<&str> = report
            .dimensions_verified
            .iter()
            .map(|s| s.as_str())
            .collect();
        let has_person = dims.contains(&"person");
        if !has_person {
            return ClassificationLabel::new("verified");
        }
        if report.independent_roots >= 2 {
            ClassificationLabel::new("certified")
        } else {
            ClassificationLabel::new("attested")
        }
    }
}

/// The verifier's acceptance policy: label → decision, per decision
/// context. This is the verifier's own risk posture, not the scheme's.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptancePolicy {
    /// Labels accepted (everything else rejected).
    pub accepted_labels: Vec<String>,
}

impl AcceptancePolicy {
    /// A policy accepting exactly `labels`.
    pub fn accept(labels: &[&str]) -> Self {
        Self {
            accepted_labels: labels.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Decide for a label.
    pub fn decide(&self, label: &ClassificationLabel) -> Acceptance {
        if self.accepted_labels.iter().any(|l| l == &label.0) {
            Acceptance::Accept
        } else {
            Acceptance::Reject
        }
    }
}

/// The acceptance decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// The artifact is accepted for this decision context.
    Accept,
    /// The artifact is rejected for this decision context.
    Reject,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(t: bool, time: bool, dims: &[&str], roots: usize) -> CoverageReport {
        CoverageReport {
            hard_checks: HardCheckStatus::Pass,
            transparency_included: t,
            time_anchored: time,
            dimensions_verified: dims.iter().map(|s| s.to_string()).collect(),
            dimension_count: dims.len(),
            independent_roots: roots,
            multi_log_quorum: false,
            paths_found: 1,
            downgrades: vec![],
        }
    }

    #[test]
    fn reference_ladder() {
        let p = ReferenceClassificationPolicy;
        assert_eq!(
            p.classify(&report(false, false, &["data"], 1)).0,
            "unverified"
        );
        assert_eq!(p.classify(&report(true, false, &["data"], 1)).0, "basic");
        assert_eq!(p.classify(&report(true, true, &["data"], 1)).0, "verified");
        assert_eq!(
            p.classify(&report(true, true, &["data", "person"], 1)).0,
            "attested"
        );
        assert_eq!(
            p.classify(&report(true, true, &["data", "person"], 2)).0,
            "certified"
        );

        let mut failed = report(true, true, &["data"], 1);
        failed.hard_checks = HardCheckStatus::Fail;
        assert_eq!(p.classify(&failed).0, "rejected");
    }

    #[test]
    fn acceptance_policy_decides_by_label() {
        let policy = AcceptancePolicy::accept(&["verified", "attested", "certified"]);
        assert_eq!(
            policy.decide(&ClassificationLabel::new("attested")),
            Acceptance::Accept
        );
        assert_eq!(
            policy.decide(&ClassificationLabel::new("basic")),
            Acceptance::Reject
        );
        assert_eq!(
            policy.decide(&ClassificationLabel::new("rejected")),
            Acceptance::Reject
        );
    }
}
