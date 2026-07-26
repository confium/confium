//! Signer attributes for predicate-based threshold signing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Attributes bound to a signer, used by predicate evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignerAttributes {
    /// Geographic region (e.g., "europe", "asia-pacific").
    pub region: Option<String>,
    /// Areas of expertise.
    pub expertise: Vec<String>,
    /// Nationality (used for conflict-of-interest exclusion).
    pub nationality: Option<String>,
    /// Roles held by the signer.
    pub role: Vec<String>,
    /// Custom attribute key-value pairs.
    pub custom: HashMap<String, String>,
}

impl SignerAttributes {
    /// Construct a new empty attribute set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the region.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Add an expertise.
    pub fn with_expertise(mut self, expertise: impl Into<String>) -> Self {
        self.expertise.push(expertise.into());
        self
    }

    /// Add a role.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role.push(role.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_attributes() {
        let attrs = SignerAttributes::new()
            .with_region("europe")
            .with_expertise("metrology")
            .with_role("director");
        assert_eq!(attrs.region.as_deref(), Some("europe"));
        assert_eq!(attrs.expertise, vec!["metrology"]);
        assert_eq!(attrs.role, vec!["director"]);
    }
}
