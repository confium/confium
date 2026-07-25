//! Escrow blob types.

use crate::metadata::EscrowMetadata;
use serde::{Deserialize, Serialize};

/// An escrowed key (or any secret) — encrypted to a threshold KEM public key.
///
/// Recovery requires T-of-N custodians to participate in an async
/// threshold decryption ceremony. The structure intentionally mirrors
/// CMS-style "envelope" patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowBlob {
    /// Identifies the recipient quorum (e.g., "biml-escrow-quorum").
    pub recipient_quorum_id: String,
    /// Threshold KEM encapsulated key (algorithm-specific bytes).
    pub encapsulated_key: Vec<u8>,
    /// AEAD ciphertext of the plaintext key, using the KEM-derived shared secret.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce.
    pub nonce: Vec<u8>,
    /// AEAD additional data (typically the metadata hash).
    pub aad: Vec<u8>,
    /// Escrow metadata.
    pub metadata: EscrowMetadata,
}

impl EscrowBlob {
    /// Compute the SHA-256 fingerprint of this blob (canonical JSON, then hash).
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.recipient_quorum_id.as_bytes());
        h.update(&self.encapsulated_key);
        h.update(&self.ciphertext);
        h.update(&self.nonce);
        h.update(&self.aad);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    }
}
