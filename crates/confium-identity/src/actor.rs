//! Actor identity types.

use crate::attributes::SignerAttributes;
use crate::token::HardwareToken;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of actor in a Confium deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// Measuring instrument manufacturer.
    Manufacturer,
    /// Testing laboratory.
    TestingLab,
    /// National issuing authority officer.
    IssuingAuthorityOfficer,
    /// BIML director (international root quorum).
    BimlDirector,
    /// Quorum coordinator service.
    QuorumCoordinator,
    /// Independent verifier.
    Verifier,
}

/// A reference to a signing key — either software-held or hardware-backed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SigningKeyHandle {
    /// In-process software key.
    Software {
        /// Key identifier.
        key_id: String,
        /// Algorithm identifier (e.g., "Ed25519", "ECDSA-P256").
        algorithm: String,
    },
    /// Hardware-backed key (HSM, YubiKey, TPM, OpenPGP card).
    Hardware {
        /// Key identifier.
        key_id: String,
        /// Algorithm identifier.
        algorithm: String,
        /// Hardware reference.
        token: HardwareToken,
    },
}

/// A reference to an encryption key — either software-held or hardware-backed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EncryptionKeyHandle {
    /// In-process software key.
    Software {
        /// Key identifier.
        key_id: String,
        /// Algorithm identifier.
        algorithm: String,
    },
    /// Hardware-backed key.
    Hardware {
        /// Key identifier.
        key_id: String,
        /// Algorithm identifier.
        algorithm: String,
        /// Hardware reference.
        token: HardwareToken,
    },
}

/// A complete actor identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorIdentity {
    /// Unique identifier (e.g., "biml-director-alice").
    pub actor_id: String,
    /// Type of actor.
    pub actor_type: ActorType,
    /// Quorum this actor belongs to (if any).
    pub quorum_id: Option<String>,
    /// Handle to the signing keypair.
    pub signing_key: SigningKeyHandle,
    /// Handle to the encryption keypair.
    pub encryption_key: Option<EncryptionKeyHandle>,
    /// X.509 certificate chain (DER-encoded), leaf first.
    pub certificate_chain_der: Vec<Vec<u8>>,
    /// Hardware token, if any.
    pub hardware_token: Option<HardwareToken>,
    /// Attribute bindings for predicate-based signing.
    pub attributes: SignerAttributes,
    /// When this identity was registered.
    pub registered_at: DateTime<Utc>,
    /// When this identity expires (if it does).
    pub expires_at: Option<DateTime<Utc>>,
}

impl ActorIdentity {
    /// Create a new actor identity builder.
    pub fn builder() -> ActorIdentityBuilder {
        ActorIdentityBuilder::default()
    }
}

/// Builder for `ActorIdentity`.
#[derive(Debug, Default, Clone)]
pub struct ActorIdentityBuilder {
    actor_id: Option<String>,
    actor_type: Option<ActorType>,
    quorum_id: Option<String>,
    signing_key: Option<SigningKeyHandle>,
    encryption_key: Option<EncryptionKeyHandle>,
    certificate_chain_der: Vec<Vec<u8>>,
    hardware_token: Option<HardwareToken>,
    attributes: SignerAttributes,
    expires_at: Option<DateTime<Utc>>,
}

impl ActorIdentityBuilder {
    /// Set the actor ID.
    pub fn actor_id(mut self, id: impl Into<String>) -> Self {
        self.actor_id = Some(id.into());
        self
    }
    /// Set the actor type.
    pub fn actor_type(mut self, t: ActorType) -> Self {
        self.actor_type = Some(t);
        self
    }
    /// Set the quorum ID.
    pub fn quorum_id(mut self, id: impl Into<String>) -> Self {
        self.quorum_id = Some(id.into());
        self
    }
    /// Set the signing key handle.
    pub fn signing_key(mut self, key: SigningKeyHandle) -> Self {
        self.signing_key = Some(key);
        self
    }
    /// Set the encryption key handle.
    pub fn encryption_key(mut self, key: EncryptionKeyHandle) -> Self {
        self.encryption_key = Some(key);
        self
    }
    /// Set the certificate chain.
    pub fn certificate_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.certificate_chain_der = chain;
        self
    }
    /// Set the hardware token.
    pub fn hardware_token(mut self, token: HardwareToken) -> Self {
        self.hardware_token = Some(token);
        self
    }
    /// Set the attributes.
    pub fn attributes(mut self, attrs: SignerAttributes) -> Self {
        self.attributes = attrs;
        self
    }
    /// Set the expiry time.
    pub fn expires_at(mut self, when: DateTime<Utc>) -> Self {
        self.expires_at = Some(when);
        self
    }

    /// Build the identity.
    pub fn build(self) -> Result<ActorIdentity, IdentityError> {
        Ok(ActorIdentity {
            actor_id: self.actor_id.ok_or(IdentityError::MissingField("actor_id"))?,
            actor_type: self.actor_type.ok_or(IdentityError::MissingField("actor_type"))?,
            quorum_id: self.quorum_id,
            signing_key: self.signing_key.ok_or(IdentityError::MissingField("signing_key"))?,
            encryption_key: self.encryption_key,
            certificate_chain_der: self.certificate_chain_der,
            hardware_token: self.hardware_token,
            attributes: self.attributes,
            registered_at: Utc::now(),
            expires_at: self.expires_at,
        })
    }
}

/// Identity errors.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Required field missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Actor not found.
    #[error("actor not found: {0}")]
    NotFound(String),
    /// Actor already exists.
    #[error("actor already exists: {0}")]
    AlreadyExists(String),
    /// Serialization error.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_identity() {
        let id = ActorIdentity::builder()
            .actor_id("biml-director-1")
            .actor_type(ActorType::BimlDirector)
            .signing_key(SigningKeyHandle::Software {
                key_id: "k1".into(),
                algorithm: "Ed25519".into(),
            })
            .build()
            .expect("build");
        assert_eq!(id.actor_id, "biml-director-1");
        assert_eq!(id.actor_type, ActorType::BimlDirector);
    }

    #[test]
    fn builder_fails_without_required_fields() {
        let result = ActorIdentity::builder().build();
        assert!(result.is_err());
    }
}
