//! Validation logic for delegated operations.

use crate::constraint::{Constraint, ScopeValue};
use crate::operation::Operation;
use crate::scope::DelegationScope;

/// Result of a delegation validation.
#[derive(Debug, Clone, Default)]
pub struct DelegationValidation {
    /// True if the operation is permitted under the scope.
    pub permitted: bool,
    /// Reasons for denial (empty if permitted).
    pub denials: Vec<DenialReason>,
}

/// Why an operation was denied.
#[derive(Debug, Clone)]
pub enum DenialReason {
    /// Operation not in allowed list.
    OperationNotAllowed(String),
    /// Constraint violated.
    ConstraintViolated(Constraint),
}

/// Validate whether `proposed_operation` is permitted under `scope`,
/// given the `actual_values` that apply.
pub fn validate_delegation(
    scope: &DelegationScope,
    proposed_operation: &Operation,
    actual_values: &[ScopeValue<'_>],
) -> DelegationValidation {
    let mut denials = Vec::new();

    let op_permitted = scope
        .allowed_operations
        .iter()
        .any(|allowed| operations_match(allowed, proposed_operation));

    if !op_permitted {
        denials.push(DenialReason::OperationNotAllowed(format!(
            "{:?}",
            proposed_operation
        )));
    }

    for constraint in &scope.constraints {
        let satisfied = actual_values.iter().any(|v| constraint.satisfies(v));
        if !satisfied {
            denials.push(DenialReason::ConstraintViolated(constraint.clone()));
        }
    }

    let permitted = denials.is_empty();
    DelegationValidation { permitted, denials }
}

fn operations_match(allowed: &Operation, proposed: &Operation) -> bool {
    matches!(
        (allowed, proposed),
        (Operation::SignCert(_), Operation::SignCert(_))
            | (Operation::SignDocument(_), Operation::SignDocument(_))
            | (Operation::ThresholdSign(_), Operation::ThresholdSign(_))
            | (Operation::Encrypt(_), Operation::Encrypt(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation::{SignCertSpec, SignDocSpec};
    use chrono::Utc;

    #[test]
    fn permitted_operation_with_satisfied_constraints() {
        let scope = DelegationScope::new()
            .allow_operation(Operation::SignCert(SignCertSpec::default()))
            .constrain(Constraint::ModelBound {
                model_id: "FM-2026-A".into(),
            });
        let values = vec![ScopeValue::ModelId("FM-2026-A")];
        let result = validate_delegation(
            &scope,
            &Operation::SignCert(SignCertSpec::default()),
            &values,
        );
        assert!(result.permitted);
        assert!(result.denials.is_empty());
    }

    #[test]
    fn denied_when_operation_not_allowed() {
        let scope =
            DelegationScope::new().allow_operation(Operation::SignCert(SignCertSpec::default()));
        let result = validate_delegation(
            &scope,
            &Operation::SignDocument(SignDocSpec::default()),
            &[],
        );
        assert!(!result.permitted);
    }

    #[test]
    fn denied_when_constraint_violated() {
        let scope = DelegationScope::new()
            .allow_operation(Operation::SignCert(SignCertSpec::default()))
            .constrain(Constraint::ModelBound {
                model_id: "FM-2026-A".into(),
            });
        let result = validate_delegation(
            &scope,
            &Operation::SignCert(SignCertSpec::default()),
            &[ScopeValue::ModelId("FM-2026-B")],
        );
        assert!(!result.permitted);
        assert_eq!(result.denials.len(), 1);
    }

    #[test]
    fn time_bound_constraint_works() {
        let now = Utc::now();
        let scope = DelegationScope::new()
            .allow_operation(Operation::SignCert(SignCertSpec::default()))
            .constrain(Constraint::TimeBound {
                not_before: now,
                not_after: now,
            });
        let result = validate_delegation(
            &scope,
            &Operation::SignCert(SignCertSpec::default()),
            &[ScopeValue::Time(now)],
        );
        assert!(result.permitted);
    }
}
