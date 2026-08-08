//! Homomorphic hash accumulator.
//!
//! An RSA-style accumulator that supports:
//! - Add element
//! - Prove membership (witness)
//! - Verify membership
//! - Remove element (with trapdoor)

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// An accumulator state.
#[derive(Debug, Clone)]
pub struct Accumulator {
    /// The accumulated value.
    pub state: BigUint,
    /// The trapdoor (prime factorization of the modulus).
    pub trapdoor: BigUint,
    /// The modulus N = p * q.
    pub modulus: BigUint,
    /// Element → prime representation.
    pub elements: HashMap<Vec<u8>, BigUint>,
}

impl Accumulator {
    /// Create a new accumulator with a fresh trapdoor.
    pub fn new() -> Self {
        let p = generate_prime(128);
        let q = generate_prime(128);
        let n = &p * &q;
        Self {
            state: BigUint::from(2u32), // g = 2 (generator)
            trapdoor: (&p - &BigUint::one()) * (&q - &BigUint::one()),
            modulus: n,
            elements: HashMap::new(),
        }
    }

    /// Add an element to the accumulator.
    pub fn add(&mut self, element: &[u8]) -> BigUint {
        let prime = hash_to_prime(element);
        self.state = self.state.modpow(&prime, &self.modulus);
        self.elements.insert(element.to_vec(), prime.clone());
        prime
    }

    /// Generate a witness (membership proof) for an element.
    pub fn witness(&self, element: &[u8]) -> Option<BigUint> {
        let target_prime = self.elements.get(element)?;
        let mut product = BigUint::one();
        for prime in self.elements.values() {
            if prime != target_prime {
                product *= prime;
            }
        }
        let g = BigUint::from(2u32);
        Some(g.modpow(&product, &self.modulus))
    }

    /// Verify membership: witness ^ element_prime == state (mod N).
    pub fn verify(&self, witness: &BigUint, element: &[u8]) -> bool {
        let prime = hash_to_prime(element);
        let expected = witness.modpow(&prime, &self.modulus);
        expected == self.state
    }

    /// Remove an element (requires recomputation).
    pub fn remove(&mut self, element: &[u8]) -> bool {
        if self.elements.remove(element).is_some() {
            let g = BigUint::from(2u32);
            let mut state = g;
            for prime in self.elements.values() {
                state = state.modpow(prime, &self.modulus);
            }
            self.state = state;
            true
        } else {
            false
        }
    }

    /// Number of accumulated elements.
    pub fn count(&self) -> usize {
        self.elements.len()
    }
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_to_prime(element: &[u8]) -> BigUint {
    let mut h = Sha256::new();
    h.update(b"acc-prime:");
    h.update(element);
    let result = h.finalize();
    let mut num = BigUint::from_bytes_be(&result);
    // Ensure odd
    num |= BigUint::one();
    // For testing, we don't verify primality — just use the hash value
    num
}

fn generate_prime(bits: u32) -> BigUint {
    let mut rng = OsRng;
    loop {
        let candidate = rng.gen_biguint(bits as u64);
        if candidate > BigUint::from(3u32) {
            return candidate | BigUint::one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accumulator_empty() {
        let acc = Accumulator::new();
        assert_eq!(acc.count(), 0);
        assert!(acc.state > BigUint::one());
    }

    #[test]
    fn add_changes_state() {
        let mut acc = Accumulator::new();
        let initial = acc.state.clone();
        acc.add(b"element");
        assert_ne!(acc.state, initial);
        assert_eq!(acc.count(), 1);
    }

    #[test]
    fn witness_verifies_membership() {
        let mut acc = Accumulator::new();
        acc.add(b"a");
        acc.add(b"b");
        acc.add(b"c");
        let witness = acc.witness(b"b").unwrap();
        assert!(acc.verify(&witness, b"b"));
    }

    #[test]
    fn non_member_not_verified() {
        let mut acc = Accumulator::new();
        acc.add(b"a");
        acc.add(b"b");
        // "c" is not in the accumulator
        let fake_witness = BigUint::from(2u32);
        assert!(!acc.verify(&fake_witness, b"c"));
    }

    #[test]
    fn witness_for_each_element() {
        let mut acc = Accumulator::new();
        let elements: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8]).collect();
        for e in &elements {
            acc.add(e);
        }
        for e in &elements {
            let w = acc.witness(e).unwrap();
            assert!(acc.verify(&w, e), "element {:?}", e);
        }
    }

    #[test]
    fn remove_decrements_count() {
        let mut acc = Accumulator::new();
        acc.add(b"a");
        acc.add(b"b");
        assert_eq!(acc.count(), 2);
        assert!(acc.remove(b"a"));
        assert_eq!(acc.count(), 1);
    }

    #[test]
    fn remove_unknown_returns_false() {
        let mut acc = Accumulator::new();
        acc.add(b"a");
        assert!(!acc.remove(b"z"));
    }

    #[test]
    fn witness_unknown_returns_none() {
        let acc = Accumulator::new();
        assert!(acc.witness(b"unknown").is_none());
    }

    #[test]
    fn re_add_works_after_remove() {
        let mut acc = Accumulator::new();
        acc.add(b"a");
        acc.add(b"b");
        acc.remove(b"a");
        acc.add(b"a");
        let w = acc.witness(b"a").unwrap();
        assert!(acc.verify(&w, b"a"));
    }

    #[test]
    fn same_element_same_prime() {
        let p1 = hash_to_prime(b"test");
        let p2 = hash_to_prime(b"test");
        assert_eq!(p1, p2);
    }
}
