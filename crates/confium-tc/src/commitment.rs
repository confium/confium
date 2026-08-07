//! Hash-based commitment scheme.
//!
//! A commitment protocol has two phases:
//!
//! 1. **Commit**: the sender picks random `r` and computes `C = H(r || m)`.
//!    They send `C` to the receiver. `C` reveals nothing about `m`
//!    (hiding) and the sender can't later claim a different `m'`
//!    (binding).
//!
//! 2. **Reveal**: the sender sends `(r, m)`. The receiver checks
//!    `H(r || m) == C`.
//!
//! Used in threshold signing nonce rounds: each party commits to
//! their nonce before any party reveals, preventing last-minute
//! adaptive attacks.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A commitment: hash of (randomness || value).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Commitment {
    /// 32-byte SHA-256 hash.
    pub hash: [u8; 32],
}

/// The decommitment: randomness + value needed to open a commitment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decommitment {
    /// 32 bytes of randomness.
    pub randomness: [u8; 32],
    /// The committed value.
    pub value: Vec<u8>,
}

impl Commitment {
    /// Create a commitment to `value` with fresh randomness.
    /// Returns (commitment, decommitment).
    pub fn create(value: &[u8]) -> (Self, Decommitment) {
        let mut randomness = [0u8; 32];
        OsRng.fill_bytes(&mut randomness);
        let hash = compute_hash(&randomness, value);
        (
            Self { hash },
            Decommitment {
                randomness,
                value: value.to_vec(),
            },
        )
    }

    /// Create a commitment with explicit randomness (for testing or
    /// deterministic protocols).
    pub fn create_with_randomness(value: &[u8], randomness: [u8; 32]) -> (Self, Decommitment) {
        let hash = compute_hash(&randomness, value);
        (
            Self { hash },
            Decommitment {
                randomness,
                value: value.to_vec(),
            },
        )
    }

    /// Verify a decommitment against this commitment.
    pub fn verify(&self, decommitment: &Decommitment) -> bool {
        let computed = compute_hash(&decommitment.randomness, &decommitment.value);
        use subtle::ConstantTimeEq;
        self.hash.ct_eq(&computed).into()
    }

    /// Serialize commitment hash as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }

    /// Deserialize from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Self { hash })
    }
}

fn compute_hash(randomness: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(randomness);
    hasher.update(value);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify_round_trips() {
        let value = b"my secret nonce";
        let (commitment, decommitment) = Commitment::create(value);
        assert!(commitment.verify(&decommitment));
    }

    #[test]
    fn commitment_hides_value() {
        let (commitment_a, _) = Commitment::create(b"value A");
        let (commitment_b, _) = Commitment::create(b"value B");
        // Different values with fresh randomness produce different commitments
        // (overwhelmingly likely — not deterministic, but probabilistically)
        assert_ne!(commitment_a.hash, commitment_b.hash);
    }

    #[test]
    fn tampered_value_rejected() {
        let (_, mut decommitment) = Commitment::create(b"original");
        let commitment = Commitment {
            hash: compute_hash(&decommitment.randomness, b"original"),
        };
        decommitment.value = b"tampered".to_vec();
        assert!(!commitment.verify(&decommitment));
    }

    #[test]
    fn tampered_randomness_rejected() {
        let (commitment, mut decommitment) = Commitment::create(b"value");
        decommitment.randomness[0] ^= 0xFF;
        assert!(!commitment.verify(&decommitment));
    }

    #[test]
    fn same_value_different_randomness() {
        let value = b"deterministic value";
        let (c1, _) = Commitment::create_with_randomness(value, [0xAA; 32]);
        let (c2, _) = Commitment::create_with_randomness(value, [0xBB; 32]);
        assert_ne!(c1.hash, c2.hash);
    }

    #[test]
    fn deterministic_creation_reproducible() {
        let value = b"test";
        let r = [0x42; 32];
        let (c1, d1) = Commitment::create_with_randomness(value, r);
        let (c2, d2) = Commitment::create_with_randomness(value, r);
        assert_eq!(c1, c2);
        assert_eq!(d1, d2);
        assert!(c1.verify(&d1));
    }

    #[test]
    fn hex_round_trip() {
        let (commitment, _) = Commitment::create(b"value");
        let hex = commitment.to_hex();
        let recovered = Commitment::from_hex(&hex).unwrap();
        assert_eq!(commitment, recovered);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert!(Commitment::from_hex("00").is_err());
        assert!(Commitment::from_hex(&"ab".repeat(31)).is_err());
        assert!(Commitment::from_hex(&"ab".repeat(33)).is_err());
    }

    #[test]
    fn empty_value_commits() {
        let (commitment, decommitment) = Commitment::create(b"");
        assert!(commitment.verify(&decommitment));
    }

    #[test]
    fn large_value_commits() {
        let value = vec![0xFFu8; 100_000];
        let (commitment, decommitment) = Commitment::create(&value);
        assert!(commitment.verify(&decommitment));
    }

    #[test]
    fn verify_uses_constant_time_comparison() {
        let (commitment, decommitment) = Commitment::create(b"value");
        // Should not panic and should return correct result
        assert!(commitment.verify(&decommitment));
    }
}
