//! Predicate AST.

// Note: serde derive removed due to infinite recursion in derive macro
// caused by the recursive Predicate type (And/Or/Not contain Predicate).
// DSL parser + manual serializers handle persistence.

/// A predicate over signer attributes.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Predicate {
    /// At least `count` signers must have `attribute`.
    MinCount {
        /// Attribute name (e.g., "role:director").
        attribute: String,
        /// Required count.
        count: usize,
    },
    /// At least `count` distinct values of `attribute` must appear.
    MinDistinct {
        /// Attribute name.
        attribute: String,
        /// Required distinct-value count.
        count: usize,
    },
    /// No signer has `attribute`.
    None {
        /// Attribute that no signer must have.
        attribute: String,
    },
    /// At least one signer has `attribute`.
    Any {
        /// Attribute that at least one signer must have.
        attribute: String,
    },
    /// All signers have `attribute`.
    All {
        /// Attribute that every signer must have.
        attribute: String,
    },
    /// Conjunction of sub-predicates.
    And(Vec<Predicate>),
    /// Disjunction of sub-predicates.
    Or(Vec<Predicate>),
    /// Negation of a sub-predicate.
    Not(Box<Predicate>),
}

/// A wrapper for type-safe construction.
#[derive(Debug, Clone)]
pub struct AttributePredicate(pub Predicate);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_constructs() {
        let p = Predicate::And(vec![
            Predicate::MinCount {
                attribute: "role:director".into(),
                count: 5,
            },
            Predicate::MinDistinct {
                attribute: "region".into(),
                count: 3,
            },
        ]);
        // Just verify the API compiles
        let AttributePredicate(_) = AttributePredicate(p.clone());
        match p {
            Predicate::And(inner) => assert_eq!(inner.len(), 2),
            _ => panic!("wrong variant"),
        }
    }
}
