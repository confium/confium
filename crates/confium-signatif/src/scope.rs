//! The multi-dimensional authorization scope lattice (SIGNATIF §11).
//!
//! A trust authority's scope is a set of independent dimensions —
//! `domain`, `subdomain`, `class`, `instance`, `identity` — each holding
//! a [`ScopeValue`] from a three-level lattice:
//!
//! ```text
//! Wildcard ⊇ Set { .. } ⊇ Single _
//! ```
//!
//! Delegation must narrow monotonically: on every dimension the child
//! value must be a subset of (or equal to) the parent value. Widening
//! any dimension at any link is a hard verification failure. Unknown
//! dimensions are carried in `extra` so schemes can extend the model
//! without breaking verifiers that do not recognize the extension; a
//! dimension absent from the parent is treated as unconstrained.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One dimension's value in the scope lattice. The default is
/// [`ScopeValue::Wildcard`]: an unconstrained dimension.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScopeValue {
    /// Unconstrained — the top of the lattice.
    #[default]
    Wildcard,
    /// One of a finite set of values.
    Set(BTreeSet<String>),
    /// Exactly one value — the bottom of the lattice.
    Single(String),
}

impl ScopeValue {
    /// Returns true when `self` is a subset of (or equal to) `parent`
    /// in the lattice: wildcard encompasses anything; a set encompasses
    /// its subsets and singles; a single encompasses only itself.
    pub fn narrows_within(&self, parent: &ScopeValue) -> bool {
        match (self, parent) {
            (_, ScopeValue::Wildcard) => true,
            (ScopeValue::Single(a), ScopeValue::Single(b)) => a == b,
            (ScopeValue::Single(a), ScopeValue::Set(sup)) => sup.contains(a),
            (ScopeValue::Set(sub), ScopeValue::Set(sup)) => sub.is_subset(sup),
            (ScopeValue::Set(_), ScopeValue::Single(_)) => false,
            (ScopeValue::Wildcard, _) => false,
        }
    }
}

/// A multi-dimensional scope: the five named SIGNATIF dimensions plus
/// an extension map for scheme-registered dimensions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDimensions {
    /// Top-level business or regulatory domain.
    pub domain: ScopeValue,
    /// Subdivision of the domain.
    pub subdomain: ScopeValue,
    /// Class of objects the authority may attest.
    pub class: ScopeValue,
    /// A specific instance identifier (batch, serial, lot).
    pub instance: ScopeValue,
    /// Authorized actor identity.
    pub identity: ScopeValue,
    /// Scheme-registered extension dimensions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, ScopeValue>,
    /// Executable scope conditions (JSON Logic subset) evaluated at
    /// verification time against the artifact and its chain (§11).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<serde_json::Value>,
}

impl ScopeDimensions {
    /// Unconstrained scope (all wildcards).
    pub fn unconstrained() -> Self {
        Self::default()
    }

    /// Iterate over `(dimension, value)` pairs, named dimensions first.
    pub fn dimensions(&self) -> impl Iterator<Item = (&'static str, &ScopeValue)> {
        [
            ("domain", &self.domain),
            ("subdomain", &self.subdomain),
            ("class", &self.class),
            ("instance", &self.instance),
            ("identity", &self.identity),
        ]
        .into_iter()
    }

    /// Look up a dimension by name, including extensions.
    pub fn get(&self, dimension: &str) -> Option<&ScopeValue> {
        match dimension {
            "domain" => Some(&self.domain),
            "subdomain" => Some(&self.subdomain),
            "class" => Some(&self.class),
            "instance" => Some(&self.instance),
            "identity" => Some(&self.identity),
            other => self.extra.get(other),
        }
    }

    /// Set a dimension value by name (including extensions).
    pub fn set(&mut self, dimension: &str, value: ScopeValue) {
        match dimension {
            "domain" => self.domain = value,
            "subdomain" => self.subdomain = value,
            "class" => self.class = value,
            "instance" => self.instance = value,
            "identity" => self.identity = value,
            other => {
                self.extra.insert(other.to_string(), value);
            }
        }
    }

    /// The monotonic narrowing invariant: `self` (child) narrows within
    /// `parent` on every dimension. Dimensions absent from the parent
    /// are unconstrained by the parent and therefore always satisfied.
    pub fn narrows_within(&self, parent: &ScopeDimensions) -> bool {
        self.first_widened_dimension(parent).is_none()
    }

    /// Returns the first dimension on which `self` widens relative to
    /// `parent`, if any — used to produce precise hard-failure errors.
    pub fn first_widened_dimension(&self, parent: &ScopeDimensions) -> Option<String> {
        for (name, child_value) in self.dimensions() {
            if let Some(parent_value) = parent.get(name) {
                if !child_value.narrows_within(parent_value) {
                    return Some(name.to_string());
                }
            }
        }
        for (name, child_value) in &self.extra {
            if let Some(parent_value) = parent.get(name) {
                if !child_value.narrows_within(parent_value) {
                    return Some(name.clone());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(s: &str) -> ScopeValue {
        ScopeValue::Single(s.into())
    }

    fn set(items: &[&str]) -> ScopeValue {
        ScopeValue::Set(items.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn lattice_narrowing() {
        let wildcard = ScopeValue::Wildcard;
        let two = set(&["pharma", "food"]);
        let one = set(&["pharma"]);
        let exact = single("pharma");

        assert!(exact.narrows_within(&one));
        assert!(one.narrows_within(&two));
        assert!(two.narrows_within(&wildcard));
        assert!(exact.narrows_within(&wildcard));

        assert!(!two.narrows_within(&one));
        assert!(!one.narrows_within(&exact));
        assert!(!single("food").narrows_within(&one));
    }

    #[test]
    fn monotonic_narrowing_invariant() {
        let mut parent = ScopeDimensions::unconstrained();
        parent.set("domain", set(&["pharma", "food"]));
        parent.set("class", single("certificate"));

        let mut child = parent.clone();
        child.set("domain", single("pharma"));
        assert!(child.narrows_within(&parent));

        let mut widening = parent.clone();
        widening.set("domain", ScopeValue::Wildcard);
        assert_eq!(
            widening.first_widened_dimension(&parent),
            Some("domain".to_string())
        );
        assert!(!widening.narrows_within(&parent));
    }

    #[test]
    fn extension_dimensions_extend_without_breaking() {
        let parent = ScopeDimensions::unconstrained();
        let mut child = ScopeDimensions::unconstrained();
        child.set("cnml:instrument-class", single("mass"));
        // Parent lacks the dimension => unconstrained => narrow holds.
        assert!(child.narrows_within(&parent));
    }
}
