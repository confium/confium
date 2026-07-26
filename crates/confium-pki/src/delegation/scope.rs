//! Delegation scope — what a child cert is authorized to do.

use crate::delegation::constraint::Constraint;
use crate::delegation::operation::Operation;
use serde::{Deserialize, Serialize};

/// The full scope of a delegated authority.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationScope {
    /// Operations the child is authorized to perform.
    pub allowed_operations: Vec<Operation>,
    /// Constraints that further narrow authorization.
    pub constraints: Vec<Constraint>,
}

impl DelegationScope {
    /// Construct a new empty scope.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an operation.
    pub fn allow_operation(mut self, op: Operation) -> Self {
        self.allowed_operations.push(op);
        self
    }

    /// Add a constraint.
    pub fn constrain(mut self, c: Constraint) -> Self {
        self.constraints.push(c);
        self
    }
}
