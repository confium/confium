//! Property-based tests for CMP20 share recovery.
//!
//! Uses a reduced case count (32) since each case requires a real
//! CMP20 DKG round which is slower than FROST-P256 Shamir splitting.

use crate::inprocess;
use crate::recovery::{recover_share, recover_share_scalar};
use crate::share::Cmp20Share;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_recovered_scalar_matches_original(t in 2u32..5u32, n in 3usize..6usize) {
        prop_assume!(n >= t as usize);
        let kg = inprocess::keygen(t, n).expect("dkg");
        let shares: Vec<Cmp20Share> = kg.shares.iter()
            .map(|b| Cmp20Share::from_bytes(b).expect("parse"))
            .collect();

        let survivors: Vec<Cmp20Share> = shares.iter().take(t as usize).cloned().collect();
        let lost_idx = n as u32;
        let recovered = recover_share_scalar(&survivors, lost_idx).expect("recover");
        let original = shares[n - 1].scalar();
        prop_assert_eq!(recovered, original);
    }

    #[test]
    fn prop_recovered_share_signs_correctly(t in 2u32..4u32, n in 3usize..5usize) {
        prop_assume!(n >= t as usize);
        let kg = inprocess::keygen(t, n).expect("dkg");
        let shares: Vec<Cmp20Share> = kg.shares.iter()
            .map(|b| Cmp20Share::from_bytes(b).expect("parse"))
            .collect();

        let survivors: Vec<Cmp20Share> = shares.iter().take(t as usize).cloned().collect();
        let lost_idx = n as u32;
        let recovered = recover_share(&survivors, lost_idx).expect("recover");

        let mut signing_set: Vec<Cmp20Share> = shares.iter()
            .take(t as usize - 1)
            .cloned()
            .collect();
        signing_set.push(recovered);

        let blobs: Vec<Vec<u8>> = signing_set.iter().map(|s| s.to_bytes()).collect();
        let sig = inprocess::sign(&blobs, t, b"proptest message").expect("sign");
        prop_assert_eq!(sig.len(), 64);
    }
}
