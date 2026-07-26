//! Threshold share type for KEM sessions.

use serde::{Deserialize, Serialize};

/// A party's share of a threshold KEM decryption key.
///
/// Analogous to `CFMTcShare` in the signing interface. Each party
/// holds one share; T-of-N shares are required to decapsulate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdShare {
    /// Algorithm identifier (must match the public key's algorithm).
    pub algorithm: String,
    /// This share's party index (0-based).
    pub party_index: u32,
    /// Raw share bytes (format depends on algorithm).
    pub bytes: Vec<u8>,
}

impl ThresholdShare {
    /// Construct a new share.
    pub fn new(algorithm: impl Into<String>, party_index: u32, bytes: Vec<u8>) -> Self {
        Self {
            algorithm: algorithm.into(),
            party_index,
            bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_construct() {
        let s = ThresholdShare::new("ElGamal-P256-threshold", 0, vec![1, 2, 3]);
        assert_eq!(s.algorithm, "ElGamal-P256-threshold");
        assert_eq!(s.party_index, 0);
        assert_eq!(s.bytes, vec![1, 2, 3]);
    }
}
