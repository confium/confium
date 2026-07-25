//! Delegation constraints.
//!
//! Constraints narrow the scope of a delegation. A child cert may
//! only exercise its delegated authority within all constraints
//! imposed by the parent.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A constraint on delegated authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Constraint {
    /// Bound to a specific model identifier (CNML Manufacturer Model Cert pattern).
    ModelBound {
        /// The model identifier.
        model_id: String,
    },
    /// Bound to a name pattern (e.g., "*.example.com").
    NameBound {
        /// The name pattern (glob).
        name_pattern: String,
    },
    /// Time-bounded delegation.
    TimeBound {
        /// When the delegation becomes valid.
        not_before: DateTime<Utc>,
        /// When the delegation expires.
        not_after: DateTime<Utc>,
    },
    /// Bounded by total issuance count.
    CountBound {
        /// Maximum number of artifacts the child may issue.
        max_issuances: u32,
    },
    /// Bounded by geographic region.
    GeographicBound {
        /// Permitted regions.
        regions: Vec<String>,
    },
    /// Bounded by subject-matter.
    SubjectBound {
        /// Permitted subjects (e.g., "metrology", "pharma").
        subjects: Vec<String>,
    },
}

impl Constraint {
    /// Check whether `value` satisfies this constraint.
    /// `value` is the actual scope value extracted from the proposed
    /// child artifact (cert, document, etc.).
    pub fn satisfies(&self, value: &ScopeValue) -> bool {
        match (self, value) {
            (Constraint::ModelBound { model_id }, ScopeValue::ModelId(actual)) => {
                model_id == actual
            }
            (Constraint::NameBound { name_pattern }, ScopeValue::Name(actual)) => {
                glob_match(name_pattern, actual)
            }
            (Constraint::TimeBound { not_before, not_after }, ScopeValue::Time(when)) => {
                when >= not_before && when <= not_after
            }
            (Constraint::CountBound { max_issuances }, ScopeValue::Count(used)) => {
                *used <= *max_issuances
            }
            (
                Constraint::GeographicBound { regions },
                ScopeValue::Region(actual),
            ) => regions.iter().any(|r| r == actual),
            (Constraint::SubjectBound { subjects }, ScopeValue::Subject(actual)) => {
                subjects.iter().any(|s| s == actual)
            }
            _ => false,
        }
    }
}

/// A scope value extracted from a child artifact, checked against constraints.
#[derive(Debug, Clone)]
pub enum ScopeValue<'a> {
    /// Model identifier.
    ModelId(&'a str),
    /// DNS-style name.
    Name(&'a str),
    /// Timestamp.
    Time(DateTime<Utc>),
    /// Count of already-issued artifacts.
    Count(u32),
    /// Geographic region.
    Region(&'a str),
    /// Subject area.
    Subject(&'a str),
}

/// Simple glob matcher: `*` matches any chars, `?` matches one char.
fn glob_match(pattern: &str, value: &str) -> bool {
    fn helper(p: &[u8], v: &[u8]) -> bool {
        match (p.first(), v.first()) {
            (Some(b'*'), _) => {
                helper(&p[1..], v) || (v.first().is_some() && helper(p, &v[1..]))
            }
            (Some(b'?'), Some(_)) => helper(&p[1..], &v[1..]),
            (Some(pc), Some(vc)) if pc == vc => helper(&p[1..], &v[1..]),
            (None, None) => true,
            _ => false,
        }
    }
    helper(pattern.as_bytes(), value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_bound_matches() {
        let c = Constraint::ModelBound {
            model_id: "FM-2026-A".into(),
        };
        assert!(c.satisfies(&ScopeValue::ModelId("FM-2026-A")));
        assert!(!c.satisfies(&ScopeValue::ModelId("FM-2026-B")));
    }

    #[test]
    fn name_bound_glob_matches() {
        let c = Constraint::NameBound {
            name_pattern: "*.example.com".into(),
        };
        assert!(c.satisfies(&ScopeValue::Name("www.example.com")));
        assert!(c.satisfies(&ScopeValue::Name("api.example.com")));
        assert!(!c.satisfies(&ScopeValue::Name("example.com")));
        assert!(!c.satisfies(&ScopeValue::Name("evil.org")));
    }

    #[test]
    fn geographic_bound_matches() {
        let c = Constraint::GeographicBound {
            regions: vec!["europe".into(), "americas".into()],
        };
        assert!(c.satisfies(&ScopeValue::Region("europe")));
        assert!(c.satisfies(&ScopeValue::Region("americas")));
        assert!(!c.satisfies(&ScopeValue::Region("asia-pacific")));
    }
}
