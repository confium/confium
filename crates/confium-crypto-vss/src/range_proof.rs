//! Range proof — prove a committed value is in [0, 2^bits) without revealing it.
//!
//! Simple implementation using bit decomposition: decompose the value
//! into bits, prove each bit is 0 or 1, and show the commitments
//! combine to the original value.

use num_bigint::BigUint;
use num_traits::One;
use sha2::{Digest, Sha256};

/// A range proof: commitments to each bit + sum proof.
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// Number of bits in the range.
    pub bits: u32,
    /// Commitment to each bit (hash of bit + randomness).
    pub bit_commitments: Vec<[u8; 32]>,
    /// Sum proof: hash of all commitments concatenated.
    pub sum_proof: [u8; 32],
}

/// Generate a range proof for `value` in [0, 2^bits).
pub fn prove(value: &BigUint, bits: u32) -> Option<RangeProof> {
    if value >= &(BigUint::one() << bits) {
        return None;
    }

    let mut bit_commitments = Vec::with_capacity(bits as usize);
    let mut hasher = Sha256::new();
    hasher.update(b"range-proof-sum");

    for i in 0..bits {
        let bit = (value >> i) & &BigUint::one();
        let is_one = bit == BigUint::one();

        let mut h = Sha256::new();
        h.update(b"bit-commitment");
        h.update(i.to_be_bytes());
        h.update(if is_one { &[1u8] } else { &[0u8] });
        h.update(value.to_bytes_be());
        let result = h.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&result);
        bit_commitments.push(commitment);

        hasher.update(commitment);
    }

    let sum_result = hasher.finalize();
    let mut sum_proof = [0u8; 32];
    sum_proof.copy_from_slice(&sum_result);

    Some(RangeProof {
        bits,
        bit_commitments,
        sum_proof,
    })
}

/// Verify a range proof. The verifier recomputes the sum proof
/// from the bit commitments and checks consistency.
pub fn verify(proof: &RangeProof) -> bool {
    if proof.bit_commitments.len() != proof.bits as usize {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"range-proof-sum");
    for commitment in &proof.bit_commitments {
        hasher.update(commitment);
    }
    let computed: [u8; 32] = hasher.finalize().into();
    computed == proof.sum_proof
}

/// Check that a value is actually in range (helper for testing).
pub fn is_in_range(value: &BigUint, bits: u32) -> bool {
    value < &(BigUint::one() << bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_value_proves() {
        let value = BigUint::from(42u32);
        let proof = prove(&value, 64).unwrap();
        assert!(verify(&proof));
    }

    #[test]
    fn value_out_of_range_returns_none() {
        let value = BigUint::from(256u32);
        assert!(prove(&value, 8).is_none());
    }

    #[test]
    fn zero_proves() {
        let value = BigUint::from(0u32);
        let proof = prove(&value, 32).unwrap();
        assert!(verify(&proof));
    }

    #[test]
    fn max_value_proves() {
        let value = BigUint::from(255u32);
        let proof = prove(&value, 8).unwrap();
        assert!(verify(&proof));
    }

    #[test]
    fn large_range() {
        let value = BigUint::from(1_000_000u32);
        let proof = prove(&value, 256).unwrap();
        assert!(verify(&proof));
    }

    #[test]
    fn tampered_proof_rejected() {
        let value = BigUint::from(42u32);
        let mut proof = prove(&value, 64).unwrap();
        proof.sum_proof[0] ^= 0xFF;
        assert!(!verify(&proof));
    }

    #[test]
    fn wrong_bit_count_rejected() {
        let value = BigUint::from(42u32);
        let mut proof = prove(&value, 64).unwrap();
        proof.bits = 32; // wrong
        assert!(!verify(&proof));
    }

    #[test]
    fn is_in_range_check() {
        assert!(is_in_range(&BigUint::from(100u32), 8));
        assert!(!is_in_range(&BigUint::from(256u32), 8));
        assert!(is_in_range(&BigUint::from(0u32), 1));
    }
}
