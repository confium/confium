//! HSM share protection interface — trait-based hardware integration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A share sealed inside an HSM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedShare {
    /// HSM-internal key handle.
    pub key_handle: String,
    /// Encrypted share blob (opaque to the host).
    pub encrypted_share: Vec<u8>,
    /// HSM-attested public key.
    pub attestation_pubkey_hex: String,
}

/// Trait for HSM share protection backends.
pub trait HsmBackend: Send + Sync {
    /// Seal (encrypt) a share inside the HSM.
    fn seal(&self, share: &[u8], label: &str) -> Result<SealedShare, HsmError>;

    /// Unseal (decrypt) a share from the HSM.
    fn unseal(&self, sealed: &SealedShare) -> Result<Vec<u8>, HsmError>;

    /// Generate a new key inside the HSM. Returns the handle.
    fn generate_key(&self, label: &str) -> Result<String, HsmError>;

    /// Delete a key from the HSM.
    fn delete_key(&self, handle: &str) -> Result<(), HsmError>;

    /// Attestation: prove the HSM is genuine.
    fn attest(&self, challenge: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Backend name.
    fn name(&self) -> &str;
}

/// HSM errors.
#[derive(Debug)]
pub enum HsmError {
    KeyNotFound(String),
    AttestationFailed,
    OperationFailed(String),
    Unsupported,
}

impl std::fmt::Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotFound(h) => write!(f, "key not found: {h}"),
            Self::AttestationFailed => write!(f, "attestation failed"),
            Self::OperationFailed(m) => write!(f, "operation failed: {m}"),
            Self::Unsupported => write!(f, "unsupported operation"),
        }
    }
}

impl std::error::Error for HsmError {}

/// Mock HSM backend (in-process, for development/testing).
#[derive(Default)]
pub struct MockHsmBackend {
    keys: std::sync::Mutex<HashMap<String, Vec<u8>>>,
    counter: std::sync::Mutex<u64>,
}

impl HsmBackend for MockHsmBackend {
    fn seal(&self, share: &[u8], label: &str) -> Result<SealedShare, HsmError> {
        let handle = format!("mock-key-{label}");
        self.keys
            .lock()
            .unwrap()
            .insert(handle.clone(), share.to_vec());
        Ok(SealedShare {
            key_handle: handle,
            encrypted_share: share.iter().map(|b| b ^ 0x42).collect(),
            attestation_pubkey_hex: "mock-attestation-pubkey".into(),
        })
    }

    fn unseal(&self, sealed: &SealedShare) -> Result<Vec<u8>, HsmError> {
        let keys = self.keys.lock().unwrap();
        match keys.get(&sealed.key_handle) {
            Some(share) => Ok(share.clone()),
            None => Err(HsmError::KeyNotFound(sealed.key_handle.clone())),
        }
    }

    fn generate_key(&self, label: &str) -> Result<String, HsmError> {
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;
        let handle = format!("mock-key-{label}-{}", *counter);
        self.keys
            .lock()
            .unwrap()
            .insert(handle.clone(), vec![0; 32]);
        Ok(handle)
    }

    fn delete_key(&self, handle: &str) -> Result<(), HsmError> {
        self.keys.lock().unwrap().remove(handle);
        Ok(())
    }

    fn attest(&self, challenge: &[u8]) -> Result<Vec<u8>, HsmError> {
        let mut result = vec![0u8; 32];
        for (i, b) in challenge.iter().enumerate() {
            result[i % 32] ^= b;
        }
        Ok(result)
    }

    fn name(&self) -> &str {
        "mock-hsm"
    }
}

/// A share vault that uses an HSM backend for protection.
pub struct ShareVault {
    backend: Box<dyn HsmBackend>,
}

impl ShareVault {
    pub fn new(backend: Box<dyn HsmBackend>) -> Self {
        Self { backend }
    }

    pub fn store(&self, party_idx: u32, share: &[u8]) -> Result<SealedShare, HsmError> {
        self.backend.seal(share, &format!("party-{party_idx}"))
    }

    pub fn retrieve(&self, sealed: &SealedShare) -> Result<Vec<u8>, HsmError> {
        self.backend.unseal(sealed)
    }

    pub fn attest(&self, challenge: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.backend.attest(challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backend_seal_unseal() {
        let hsm = MockHsmBackend::default();
        let sealed = hsm.seal(b"secret share", "test").unwrap();
        let recovered = hsm.unseal(&sealed).unwrap();
        assert_eq!(recovered, b"secret share");
    }

    #[test]
    fn mock_backend_key_not_found() {
        let hsm = MockHsmBackend::default();
        let sealed = SealedShare {
            key_handle: "nonexistent".into(),
            encrypted_share: vec![],
            attestation_pubkey_hex: "".into(),
        };
        assert!(matches!(hsm.unseal(&sealed), Err(HsmError::KeyNotFound(_))));
    }

    #[test]
    fn mock_backend_generate_and_delete() {
        let hsm = MockHsmBackend::default();
        let handle = hsm.generate_key("test").unwrap();
        hsm.delete_key(&handle).unwrap();
    }

    #[test]
    fn mock_backend_attest() {
        let hsm = MockHsmBackend::default();
        let attestation = hsm.attest(b"challenge").unwrap();
        assert_eq!(attestation.len(), 32);
    }

    #[test]
    fn vault_store_retrieve() {
        let vault = ShareVault::new(Box::new(MockHsmBackend::default()));
        let sealed = vault.store(1, b"party-1-share").unwrap();
        let recovered = vault.retrieve(&sealed).unwrap();
        assert_eq!(recovered, b"party-1-share");
    }

    #[test]
    fn vault_attest() {
        let vault = ShareVault::new(Box::new(MockHsmBackend::default()));
        let attestation = vault.attest(b"nonce").unwrap();
        assert_eq!(attestation.len(), 32);
    }

    #[test]
    fn different_labels_different_handles() {
        let hsm = MockHsmBackend::default();
        let s1 = hsm.seal(b"a", "label1").unwrap();
        let s2 = hsm.seal(b"b", "label2").unwrap();
        assert_ne!(s1.key_handle, s2.key_handle);
    }

    #[test]
    fn backend_name() {
        let hsm = MockHsmBackend::default();
        assert_eq!(hsm.name(), "mock-hsm");
    }
}
