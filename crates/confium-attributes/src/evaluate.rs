//! Predicate evaluation.

use crate::ast::Predicate;
use std::collections::{HashMap, HashSet};

/// A signer's attribute map. Keys are attribute names (e.g., "region",
/// "role:director", "expertise:metrology"). Values are sets of strings.
#[derive(Debug, Clone, Default)]
pub struct SignerAttributes {
    pub attrs: HashMap<String, HashSet<String>>,
}

impl SignerAttributes {
    /// Construct empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a value to an attribute.
    pub fn add(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attrs
            .entry(key.into())
            .or_default()
            .insert(value.into());
    }

    /// Does this signer have attribute `key`?
    pub fn has(&self, key: &str) -> bool {
        self.attrs.contains_key(key) && !self.attrs[key].is_empty()
    }

    /// Get the values for `key`.
    pub fn values(&self, key: &str) -> Vec<String> {
        self.attrs
            .get(key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Evaluate `predicate` against a list of `signers`. Returns `true` iff satisfied.
pub fn evaluate(predicate: &Predicate, signers: &[&SignerAttributes]) -> bool {
    match predicate {
        Predicate::MinCount { attribute, count } => {
            let n = signers.iter().filter(|s| s.has(attribute)).count();
            n >= *count
        }
        Predicate::MinDistinct { attribute, count } => {
            let all_values: HashSet<&str> = signers
                .iter()
                .flat_map(|s| s.attrs.get(attribute).into_iter().flatten())
                .map(|s| s.as_str())
                .collect();
            all_values.len() >= *count
        }
        Predicate::None { attribute } => !signers.iter().any(|s| s.has(attribute)),
        Predicate::Any { attribute } => signers.iter().any(|s| s.has(attribute)),
        Predicate::All { attribute } => {
            !signers.is_empty() && signers.iter().all(|s| s.has(attribute))
        }
        Predicate::And(preds) => preds.iter().all(|p| evaluate(p, signers)),
        Predicate::Or(preds) => preds.iter().any(|p| evaluate(p, signers)),
        Predicate::Not(p) => !evaluate(p, signers),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> SignerAttributes {
        let mut a = SignerAttributes::new();
        a.add("role:director", "yes");
        a.add("region", "europe");
        a.add("expertise", "metrology");
        a
    }

    fn bob() -> SignerAttributes {
        let mut a = SignerAttributes::new();
        a.add("role:director", "yes");
        a.add("region", "americas");
        a
    }

    fn carol() -> SignerAttributes {
        let mut a = SignerAttributes::new();
        a.add("role:director", "yes");
        a.add("region", "asia-pacific");
        a
    }

    #[test]
    fn min_count_satisfied() {
        let a = alice();
        let b = bob();
        let c = carol();
        let signers = vec![&a, &b, &c];
        let pred = Predicate::MinCount {
            attribute: "role:director".into(),
            count: 3,
        };
        assert!(evaluate(&pred, &signers));
    }

    #[test]
    fn min_count_not_satisfied() {
        let a = alice();
        let b = bob();
        let signers = vec![&a, &b];
        let pred = Predicate::MinCount {
            attribute: "role:director".into(),
            count: 3,
        };
        assert!(!evaluate(&pred, &signers));
    }

    #[test]
    fn min_distinct_geography() {
        let a = alice();
        let b = bob();
        let c = carol();
        let signers = vec![&a, &b, &c];
        let pred = Predicate::MinDistinct {
            attribute: "region".into(),
            count: 3,
        };
        assert!(evaluate(&pred, &signers));
    }

    #[test]
    fn none_predicate_blocks_signer() {
        let a = alice();
        let b = bob();
        let signers = vec![&a, &b];
        let pred = Predicate::None {
            attribute: "nationality:cn".into(),
        };
        assert!(evaluate(&pred, &signers));
    }

    #[test]
    fn boolean_composition() {
        let a = alice();
        let b = bob();
        let c = carol();
        let signers = vec![&a, &b, &c];
        let pred = Predicate::And(vec![
            Predicate::MinCount {
                attribute: "role:director".into(),
                count: 3,
            },
            Predicate::MinDistinct {
                attribute: "region".into(),
                count: 3,
            },
            Predicate::Any {
                attribute: "expertise".into(),
            },
        ]);
        assert!(evaluate(&pred, &signers));
    }

    #[test]
    fn or_composition() {
        let a = alice();
        let signers = vec![&a];
        let pred = Predicate::Or(vec![
            Predicate::MinCount {
                attribute: "role:director".into(),
                count: 5,
            },
            Predicate::Any {
                attribute: "expertise".into(),
            },
        ]);
        assert!(evaluate(&pred, &signers));
    }
}
