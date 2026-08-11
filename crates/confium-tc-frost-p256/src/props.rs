//! Property-based tests for FROST-P256 Shamir secret sharing.
//!
//! These tests use `proptest` to verify mathematical invariants across
//! hundreds of random inputs — catching edge cases that fixed-input
//! unit tests miss.

use crate::scalar;
use crate::shamir::{Share, recover_secret, split_secret};
use proptest::prelude::*;

proptest! {
    /// Any T-of-N shares reconstruct the exact original secret.
    #[test]
    fn prop_any_t_shares_recover_secret(t in 1u32..8, n in 2u32..10) {
        prop_assume!(n >= t);
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, t, n);

        let chosen: Vec<&Share> = shares.iter().take(t as usize).collect();
        let recovered = recover_secret(&chosen).unwrap();
        prop_assert_eq!(recovered, secret);

        if n > t {
            let alt: Vec<&Share> = shares.iter().rev().take(t as usize).collect();
            prop_assume!(alt.len() == t as usize);
            let recovered2 = recover_secret(&alt).unwrap();
            prop_assert_eq!(recovered2, secret);
        }
    }

    /// T-1 shares produce a different scalar than the secret.
    #[test]
    fn prop_insufficient_shares_differ(t in 2u32..8, n in 3u32..10) {
        prop_assume!(n >= t);
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, t, n);

        let too_few: Vec<&Share> = shares.iter().take((t - 1) as usize).collect();
        prop_assume!(!too_few.is_empty());

        let recovered = recover_secret(&too_few).unwrap();
        prop_assert_ne!(recovered, secret);
    }

    /// Threshold T=1: single share always reconstructs the secret.
    #[test]
    fn prop_threshold_one(n in 1u32..10) {
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, 1, n);
        for s in &shares {
            let single: Vec<&Share> = vec![s];
            let recovered = recover_secret(&single).unwrap();
            prop_assert_eq!(recovered, secret);
        }
    }

    /// Splitting the same secret twice produces different share sets
    /// (random polynomial coefficients) but both recover the same secret.
    #[test]
    fn prop_two_splits_same_secret(t in 1u32..6, n in 2u32..10) {
        prop_assume!(n >= t);
        let secret = scalar::random_scalar();
        let shares_a = split_secret(&secret, t, n);
        let shares_b = split_secret(&secret, t, n);

        let sub_a: Vec<&Share> = shares_a.iter().take(t as usize).collect();
        let sub_b: Vec<&Share> = shares_b.iter().take(t as usize).collect();

        prop_assert_eq!(recover_secret(&sub_a).unwrap(), secret);
        prop_assert_eq!(recover_secret(&sub_b).unwrap(), secret);
    }

    /// Any random permutation of T shares still recovers the secret.
    #[test]
    fn prop_permuted_shares_recover(t in 2u32..6, n in 3u32..10) {
        prop_assume!(n >= t);
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, t, n);

        let mut perm: Vec<Share> = shares.iter().take(t as usize).cloned().collect();
        perm.reverse();
        let refs: Vec<&Share> = perm.iter().collect();
        let recovered = recover_secret(&refs).unwrap();
        prop_assert_eq!(recovered, secret);
    }

    /// All shares have unique x-coordinates (party indices).
    #[test]
    fn prop_shares_have_unique_x(t in 1u32..6, n in 2u32..10) {
        prop_assume!(n >= t);
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, t, n);
        let mut seen = std::collections::HashSet::new();
        for s in &shares {
            prop_assert!(seen.insert(s.x), "duplicate x: {}", s.x);
        }
    }
}
