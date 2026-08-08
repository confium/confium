//! Threshold attribute-based signing.
//!
//! Sign if the signer's attributes satisfy a policy AND enough
//! signers (threshold) participate. Combines attribute-based access
//! control with threshold signing.

use serde::{Deserialize, Serialize};

/// An attribute value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Attribute {
    Region(String),
    Role(String),
    Clearance(u32),
    Department(String),
}

/// A signing policy: attributes that must be satisfied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignPolicy {
    /// Required attributes (all must be present).
    pub required: Vec<Attribute>,
    /// Minimum number of qualifying signers.
    pub threshold: u32,
}

/// A signer with attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSigner {
    pub id: String,
    pub attributes: Vec<Attribute>,
}

/// Check if a signer satisfies the required attributes.
pub fn satisfies_policy(signer: &AttributeSigner, policy: &SignPolicy) -> bool {
    for req in &policy.required {
        if !signer.attributes.contains(req) {
            return false;
        }
    }
    true
}

/// A signing session with attribute-based access control.
#[derive(Debug)]
pub struct AbsSession {
    pub policy: SignPolicy,
    pub signers: Vec<AttributeSigner>,
    pub authorized: Vec<String>,
}

impl AbsSession {
    pub fn new(policy: SignPolicy) -> Self {
        Self {
            policy,
            signers: Vec::new(),
            authorized: Vec::new(),
        }
    }

    /// Add a signer. Returns true if they satisfy the policy.
    pub fn add_signer(&mut self, signer: AttributeSigner) -> bool {
        let authorized = satisfies_policy(&signer, &self.policy);
        if authorized {
            self.authorized.push(signer.id.clone());
        }
        self.signers.push(signer);
        authorized
    }

    /// Can the session proceed? (enough authorized signers)
    pub fn can_sign(&self) -> bool {
        self.authorized.len() >= self.policy.threshold as usize
    }

    /// Number of authorized signers.
    pub fn authorized_count(&self) -> usize {
        self.authorized.len()
    }

    /// List authorized signer IDs.
    pub fn authorized_ids(&self) -> &[String] {
        &self.authorized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy() -> SignPolicy {
        SignPolicy {
            required: vec![
                Attribute::Role("director".into()),
                Attribute::Region("eu".into()),
            ],
            threshold: 2,
        }
    }

    #[test]
    fn satisfies_policy_all_attributes() {
        let signer = AttributeSigner {
            id: "alice".into(),
            attributes: vec![
                Attribute::Role("director".into()),
                Attribute::Region("eu".into()),
            ],
        };
        assert!(satisfies_policy(&signer, &make_policy()));
    }

    #[test]
    fn missing_attribute_fails() {
        let signer = AttributeSigner {
            id: "bob".into(),
            attributes: vec![Attribute::Role("director".into())],
        };
        assert!(!satisfies_policy(&signer, &make_policy()));
    }

    #[test]
    fn session_threshold_met() {
        let mut session = AbsSession::new(make_policy());
        session.add_signer(AttributeSigner {
            id: "alice".into(),
            attributes: vec![
                Attribute::Role("director".into()),
                Attribute::Region("eu".into()),
            ],
        });
        session.add_signer(AttributeSigner {
            id: "bob".into(),
            attributes: vec![
                Attribute::Role("director".into()),
                Attribute::Region("eu".into()),
            ],
        });
        assert!(session.can_sign());
        assert_eq!(session.authorized_count(), 2);
    }

    #[test]
    fn session_threshold_not_met() {
        let mut session = AbsSession::new(make_policy());
        session.add_signer(AttributeSigner {
            id: "alice".into(),
            attributes: vec![
                Attribute::Role("director".into()),
                Attribute::Region("eu".into()),
            ],
        });
        assert!(!session.can_sign());
    }

    #[test]
    fn unauthorized_signers_not_counted() {
        let mut session = AbsSession::new(make_policy());
        session.add_signer(AttributeSigner {
            id: "alice".into(),
            attributes: vec![
                Attribute::Role("director".into()),
                Attribute::Region("eu".into()),
            ],
        });
        session.add_signer(AttributeSigner {
            id: "bob".into(),
            attributes: vec![Attribute::Role("analyst".into())], // wrong role
        });
        assert!(!session.can_sign());
        assert_eq!(session.authorized_count(), 1);
    }

    #[test]
    fn clearance_attribute() {
        let policy = SignPolicy {
            required: vec![Attribute::Clearance(5)],
            threshold: 1,
        };
        let signer = AttributeSigner {
            id: "alice".into(),
            attributes: vec![Attribute::Clearance(5)],
        };
        assert!(satisfies_policy(&signer, &policy));
    }

    #[test]
    fn different_clearance_fails() {
        let policy = SignPolicy {
            required: vec![Attribute::Clearance(5)],
            threshold: 1,
        };
        let signer = AttributeSigner {
            id: "alice".into(),
            attributes: vec![Attribute::Clearance(3)],
        };
        assert!(!satisfies_policy(&signer, &policy));
    }

    #[test]
    fn authorized_ids_listed() {
        let mut session = AbsSession::new(make_policy());
        session.add_signer(AttributeSigner {
            id: "alice".into(),
            attributes: vec![
                Attribute::Role("director".into()),
                Attribute::Region("eu".into()),
            ],
        });
        assert_eq!(session.authorized_ids(), &["alice"]);
    }
}
