//! Dispatch layer — routes PKCS#11 calls to threshold protocol.

use crate::slot::{SlotId, SlotInfo};
use crate::token::TokenInfo;
use std::collections::HashMap;

/// Errors during PKCS#11 dispatch.
#[derive(Debug, thiserror::Error)]
pub enum Pkcs11Error {
    /// Slot not present.
    #[error("slot {0:?} not present")]
    SlotNotPresent(SlotId),
    /// Threshold signing failed.
    #[error("threshold signing failed: {0}")]
    SignFailed(String),
    /// Threshold decryption failed.
    #[error("threshold decryption failed: {0}")]
    DecryptFailed(String),
    /// Function not supported.
    #[error("function {0} not supported")]
    UnsupportedFunction(String),
    /// PIN incorrect.
    #[error("PIN incorrect")]
    BadPin,
}

/// Signer trait — caller provides the actual coordinator dispatch.
pub trait QuorumDispatcher: Send + Sync {
    /// Sign `data` using the threshold quorum at `slot`. Returns signature bytes.
    fn sign(&self, slot: SlotId, data: &[u8]) -> Result<Vec<u8>, String>;

    /// Decrypt `ciphertext` using the threshold quorum at `slot`. Returns plaintext.
    fn decrypt(&self, slot: SlotId, ciphertext: &[u8]) -> Result<Vec<u8>, String>;

    /// Trigger a DKG for a new threshold keypair.
    fn generate_keypair(&self, slot: SlotId) -> Result<Vec<u8>, String>;
}

/// The PKCS#11 dispatch service.
pub struct Pkcs11Server {
    slots: HashMap<SlotId, SlotInfo>,
    tokens: HashMap<SlotId, TokenInfo>,
    dispatcher: Box<dyn QuorumDispatcher>,
}

impl Pkcs11Server {
    /// Construct a new server backed by `dispatcher`.
    pub fn new(dispatcher: Box<dyn QuorumDispatcher>) -> Self {
        Self {
            slots: HashMap::new(),
            tokens: HashMap::new(),
            dispatcher,
        }
    }

    /// Register a slot for a Confium quorum.
    pub fn register_quorum(
        &mut self,
        slot: SlotId,
        slot_info: SlotInfo,
        token_info: TokenInfo,
    ) {
        self.slots.insert(slot.clone(), slot_info);
        self.tokens.insert(slot, token_info);
    }

    /// `C_Sign` — sign data via threshold protocol.
    pub fn c_sign(&self, slot: SlotId, data: &[u8]) -> Result<Vec<u8>, Pkcs11Error> {
        if !self.slots.contains_key(&slot) {
            return Err(Pkcs11Error::SlotNotPresent(slot));
        }
        self.dispatcher
            .sign(slot.clone(), data)
            .map_err(Pkcs11Error::SignFailed)
    }

    /// `C_Decrypt` — decrypt via threshold protocol.
    pub fn c_decrypt(&self, slot: SlotId, ciphertext: &[u8]) -> Result<Vec<u8>, Pkcs11Error> {
        if !self.slots.contains_key(&slot) {
            return Err(Pkcs11Error::SlotNotPresent(slot));
        }
        self.dispatcher
            .decrypt(slot.clone(), ciphertext)
            .map_err(Pkcs11Error::DecryptFailed)
    }

    /// `C_GenerateKeyPair` — trigger DKG.
    pub fn c_generate_keypair(&self, slot: SlotId) -> Result<Vec<u8>, Pkcs11Error> {
        if !self.slots.contains_key(&slot) {
            return Err(Pkcs11Error::SlotNotPresent(slot));
        }
        self.dispatcher
            .generate_keypair(slot)
            .map_err(Pkcs11Error::SignFailed)
    }

    /// Get slot info.
    pub fn slot_info(&self, slot: &SlotId) -> Option<&SlotInfo> {
        self.slots.get(slot)
    }

    /// Get token info.
    pub fn token_info(&self, slot: &SlotId) -> Option<&TokenInfo> {
        self.tokens.get(slot)
    }

    /// Number of registered slots.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDispatcher;
    impl QuorumDispatcher for MockDispatcher {
        fn sign(&self, _slot: SlotId, data: &[u8]) -> Result<Vec<u8>, String> {
            Ok(data.iter().map(|b| !b).collect())
        }
        fn decrypt(&self, _slot: SlotId, ct: &[u8]) -> Result<Vec<u8>, String> {
            Ok(ct.to_vec())
        }
        fn generate_keypair(&self, _slot: SlotId) -> Result<Vec<u8>, String> {
            Ok(vec![0u8; 32])
        }
    }

    #[test]
    fn full_pkcs11_lifecycle() {
        let mut server = Pkcs11Server::new(Box::new(MockDispatcher));
        let slot = SlotId(1);
        server.register_quorum(
            slot,
            SlotInfo::for_quorum("test-quorum"),
            TokenInfo::for_quorum(
                SlotId(1),
                "test-quorum",
                2,
                3,
                "FROST-P256",
                "coordinator.example.com:443",
            ),
        );
        assert_eq!(server.slot_count(), 1);

        let sig = server.c_sign(SlotId(1), b"hello").unwrap();
        // !b'h' = 0x97, !b'e' = 0x9a, !b'l' = 0x93, !b'l' = 0x93, !b'o' = 0x90
        assert_eq!(sig, vec![0x97, 0x9a, 0x93, 0x93, 0x90]);

        let pt = server.c_decrypt(SlotId(1), b"cipher").unwrap();
        assert_eq!(pt, b"cipher");

        let pk = server.c_generate_keypair(SlotId(1)).unwrap();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn unknown_slot_fails() {
        let server = Pkcs11Server::new(Box::new(MockDispatcher));
        let result = server.c_sign(SlotId(99), b"data");
        assert!(matches!(result, Err(Pkcs11Error::SlotNotPresent(_))));
    }
}
