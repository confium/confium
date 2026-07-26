//! Escrow service — encrypts and recovers keys.

use crate::escrow::blob::EscrowBlob;
use crate::escrow::metadata::EscrowMetadata;

/// Errors during escrow operations.
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    /// Encapsulation failure.
    #[error("encapsulation failure: {0}")]
    Encapsulate(String),
    /// AEAD encryption failure.
    #[error("AEAD encryption failure: {0}")]
    AeadEncrypt(String),
    /// Decapsulation failure (threshold decryption ceremony failed).
    #[error("decapsulation failure: {0}")]
    Decapsulate(String),
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Number of partial decryptions collected.
        have: usize,
        /// Threshold T.
        need: u32,
    },
    /// Invalid blob.
    #[error("invalid blob: {0}")]
    InvalidBlob(String),
}

/// Quorum public key (recipient of escrowed data).
#[derive(Debug, Clone)]
pub struct QuorumPublicKey {
    /// Quorum identifier.
    pub quorum_id: String,
    /// Algorithm.
    pub algorithm: String,
    /// Raw public key bytes.
    pub bytes: Vec<u8>,
    /// Number of custodians N.
    pub custodian_count: u32,
    /// Threshold T.
    pub threshold: u32,
}

/// Encapsulator hook — caller provides concrete threshold KEM implementation.
pub trait Encapsulator {
    /// Encapsulate to the quorum public key. Returns (encapsulated_key, shared_secret).
    fn encapsulate(&self, recipient: &QuorumPublicKey) -> Result<(Vec<u8>, Vec<u8>), EscrowError>;
}

/// AEAD hook — caller provides concrete AEAD implementation.
pub trait Aead {
    /// Encrypt plaintext with shared_secret as key. Returns (ciphertext, nonce).
    fn encrypt(
        &self,
        shared_secret: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), EscrowError>;

    /// Decrypt ciphertext with shared_secret as key.
    fn decrypt(
        &self,
        shared_secret: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EscrowError>;
}

/// The escrow service.
pub struct EscrowService;

impl EscrowService {
    /// Construct a new escrow service.
    pub fn new() -> Self {
        Self
    }

    /// Escrow a key (or any secret) to a recipient quorum.
    pub fn escrow(
        &self,
        plaintext_key: &[u8],
        recipient: &QuorumPublicKey,
        escrowed_by: &str,
        key_id: &str,
        key_type: &str,
        encapsulator: &dyn Encapsulator,
        aead: &dyn Aead,
    ) -> Result<EscrowBlob, EscrowError> {
        let metadata = EscrowMetadata::new(
            escrowed_by,
            key_id,
            key_type,
            recipient.custodian_count,
            recipient.threshold,
        );
        let aad = metadata_string(&metadata);

        let (encapsulated_key, shared_secret) = encapsulator.encapsulate(recipient)?;
        let (ciphertext, nonce) = aead.encrypt(&shared_secret, plaintext_key, aad.as_bytes())?;

        Ok(EscrowBlob {
            recipient_quorum_id: recipient.quorum_id.clone(),
            encapsulated_key,
            ciphertext,
            nonce,
            aad: aad.into_bytes(),
            metadata,
        })
    }

    /// Recover a key from a blob, given the recovered shared secret.
    ///
    /// The caller is responsible for running the threshold decryption
    /// ceremony to recover the shared secret (typically via
    /// `confium-tc-kem`). This function takes the recovered secret
    /// and performs the final AEAD decryption.
    pub fn recover(
        &self,
        blob: &EscrowBlob,
        shared_secret: &[u8],
        aead: &dyn Aead,
    ) -> Result<Vec<u8>, EscrowError> {
        aead.decrypt(
            shared_secret,
            &blob.ciphertext,
            &blob.nonce,
            &blob.aad,
        )
    }
}

impl Default for EscrowService {
    fn default() -> Self {
        Self::new()
    }
}

fn metadata_string(m: &EscrowMetadata) -> String {
    // Lightweight deterministic encoding (canonical JSON via serde_json::to_string).
    serde_json::to_string(m).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock encapsulator: returns the public key bytes as encapsulated,
    /// 32 zero bytes as shared secret.
    struct MockEncapsulator;
    impl Encapsulator for MockEncapsulator {
        fn encapsulate(&self, recipient: &QuorumPublicKey) -> Result<(Vec<u8>, Vec<u8>), EscrowError> {
            Ok((recipient.bytes.clone(), vec![0u8; 32]))
        }
    }

    /// Mock AEAD: XOR plaintext with shared_secret (truncated/extended).
    struct MockAead;
    impl Aead for MockAead {
        fn encrypt(
            &self,
            shared_secret: &[u8],
            plaintext: &[u8],
            _aad: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), EscrowError> {
            let mut ct = vec![0u8; plaintext.len()];
            for (i, b) in plaintext.iter().enumerate() {
                ct[i] = b ^ shared_secret[i % shared_secret.len()];
            }
            Ok((ct, vec![0u8; 12]))
        }
        fn decrypt(
            &self,
            shared_secret: &[u8],
            ciphertext: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
        ) -> Result<Vec<u8>, EscrowError> {
            let mut pt = vec![0u8; ciphertext.len()];
            for (i, b) in ciphertext.iter().enumerate() {
                pt[i] = b ^ shared_secret[i % shared_secret.len()];
            }
            Ok(pt)
        }
    }

    fn sample_quorum() -> QuorumPublicKey {
        QuorumPublicKey {
            quorum_id: "test-quorum".into(),
            algorithm: "mock-threshold-kem".into(),
            bytes: vec![1u8; 32],
            custodian_count: 3,
            threshold: 2,
        }
    }

    #[test]
    fn escrow_then_recover_round_trips() {
        let service = EscrowService::new();
        let quorum = sample_quorum();
        let plaintext = b"this is a very secret key";

        let blob = service
            .escrow(
                plaintext,
                &quorum,
                "alice",
                "key-1",
                "Ed25519",
                &MockEncapsulator,
                &MockAead,
            )
            .unwrap();

        // In real usage, this would come from a threshold decryption ceremony.
        let shared_secret = vec![0u8; 32];
        let recovered = service.recover(&blob, &shared_secret, &MockAead).unwrap();

        assert_eq!(recovered.as_slice(), plaintext);
        assert_eq!(blob.metadata.threshold, 2);
        assert_eq!(blob.metadata.custodian_count, 3);
    }

    #[test]
    fn blob_has_fingerprint() {
        let service = EscrowService::new();
        let blob = service
            .escrow(
                b"test",
                &sample_quorum(),
                "alice",
                "key-1",
                "Ed25519",
                &MockEncapsulator,
                &MockAead,
            )
            .unwrap();
        let fp = blob.fingerprint();
        assert_eq!(fp.len(), 32);
    }
}
