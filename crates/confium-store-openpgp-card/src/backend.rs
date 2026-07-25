//! OpenPGP card backend interface + mock implementation.

use crate::slot::OpenpgpSlot;
use serde::{Deserialize, Serialize};

/// An OpenPGP card identifier (typically derived from the card's serial number).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardId(pub String);

/// Errors during OpenPGP card operations.
#[derive(Debug, thiserror::Error)]
pub enum CardError {
    /// Card not present (no reader, no card inserted).
    #[error("card not present: {0}")]
    NotPresent(String),
    /// PIN blocked (after too many wrong attempts).
    #[error("PIN blocked")]
    PinBlocked,
    /// Wrong PIN.
    #[error("wrong PIN ({attempts_remaining} attempts remaining)")]
    WrongPin {
        /// Remaining attempts.
        attempts_remaining: u32,
    },
    /// Slot not configured (no key generated).
    #[error("slot {0:?} not configured")]
    SlotNotConfigured(OpenpgpSlot),
    /// Operation requires verification.
    #[error("verification required for {0}")]
    VerificationRequired(String),
    /// I/O error communicating with the card.
    #[error("card I/O error: {0}")]
    Io(String),
}

/// Backend trait for talking to OpenPGP cards.
pub trait OpenpgpCardBackend: Send + Sync {
    /// Get the card identifier.
    fn card_id(&self) -> Result<CardId, CardError>;

    /// Generate a new keypair in the given slot. Returns the public key bytes.
    fn generate_keypair(
        &self,
        slot: OpenpgpSlot,
        algorithm: &str,
    ) -> Result<Vec<u8>, CardError>;

    /// Import a keypair into the given slot (rare; usually generated in-card).
    fn import_keypair(
        &self,
        slot: OpenpgpSlot,
        private_key: &[u8],
    ) -> Result<(), CardError>;

    /// Get the public key from a slot.
    fn public_key(&self, slot: OpenpgpSlot) -> Result<Vec<u8>, CardError>;

    /// Sign data using the SIG slot.
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CardError>;

    /// Decrypt data using the DEC slot.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CardError>;

    /// Verify the user PIN.
    fn verify_pin(&self, pin: &str) -> Result<(), CardError>;

    /// Verify the admin PIN.
    fn verify_admin_pin(&self, admin_pin: &str) -> Result<(), CardError>;

    /// Reset the card (wipes all keys; requires admin or special procedure).
    fn factory_reset(&self) -> Result<(), CardError>;
}

/// In-memory mock backend (no hardware). Testing only.
pub struct MockOpenpgpCardBackend {
    card_id: CardId,
    keys: std::collections::HashMap<OpenpgpSlot, Vec<u8>>,
    pin_verified: bool,
    admin_verified: bool,
}

impl MockOpenpgpCardBackend {
    /// Construct a new mock backend.
    pub fn new(card_id: impl Into<String>) -> Self {
        Self {
            card_id: CardId(card_id.into()),
            keys: std::collections::HashMap::new(),
            pin_verified: false,
            admin_verified: false,
        }
    }
}

impl OpenpgpCardBackend for MockOpenpgpCardBackend {
    fn card_id(&self) -> Result<CardId, CardError> {
        Ok(self.card_id.clone())
    }

    fn generate_keypair(
        &self,
        slot: OpenpgpSlot,
        algorithm: &str,
    ) -> Result<Vec<u8>, CardError> {
        if !self.admin_verified {
            return Err(CardError::VerificationRequired("admin PIN".into()));
        }
        let _ = algorithm;
        // Mock: deterministic public key derived from slot
        Ok(vec![slot as u8; 32])
    }

    fn import_keypair(
        &self,
        _slot: OpenpgpSlot,
        _private_key: &[u8],
    ) -> Result<(), CardError> {
        if !self.admin_verified {
            return Err(CardError::VerificationRequired("admin PIN".into()));
        }
        Ok(())
    }

    fn public_key(&self, slot: OpenpgpSlot) -> Result<Vec<u8>, CardError> {
        self.keys
            .get(&slot)
            .cloned()
            .or_else(|| Some(vec![slot as u8; 32]))
            .ok_or_else(|| CardError::SlotNotConfigured(slot))
    }

    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CardError> {
        if !self.pin_verified {
            return Err(CardError::VerificationRequired("user PIN".into()));
        }
        Ok(digest.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CardError> {
        if !self.pin_verified {
            return Err(CardError::VerificationRequired("user PIN".into()));
        }
        Ok(ciphertext.to_vec())
    }

    fn verify_pin(&self, _pin: &str) -> Result<(), CardError> {
        // Mock always succeeds (can't mutate self in this trait shape)
        Ok(())
    }

    fn verify_admin_pin(&self, _admin_pin: &str) -> Result<(), CardError> {
        Ok(())
    }

    fn factory_reset(&self) -> Result<(), CardError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backend_card_id() {
        let backend = MockOpenpgpCardBackend::new("YubiKey-001234");
        let id = backend.card_id().unwrap();
        assert_eq!(id.0, "YubiKey-001234");
    }

    #[test]
    fn mock_backend_sign_without_pin_fails() {
        let backend = MockOpenpgpCardBackend::new("test");
        let result = backend.sign(b"hello");
        assert!(matches!(result, Err(CardError::VerificationRequired(_))));
    }
}
