//! Secure aggregation protocol.
//!
//! Google-style secure aggregation: N parties each hold a private
//! value, and want to compute the SUM without revealing any individual
//! value. Uses pairwise masking (each pair shares a mask that cancels
//! when summed).

use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::rand_core::RngCore;
use std::collections::HashMap;

/// A party in the secure aggregation.
#[derive(Debug, Clone)]
pub struct AggregationParty {
    pub id: u32,
    pub value: i64,
    /// Masks shared with other parties: mask[i][j] = random value
    /// added by i, subtracted by j.
    pub masks_to_apply: HashMap<u32, i64>,
}

/// The secure aggregation session.
#[derive(Debug)]
pub struct SecureAggregation {
    pub parties: Vec<AggregationParty>,
}

impl SecureAggregation {
    pub fn new(party_count: u32) -> Self {
        let parties = (0..party_count)
            .map(|id| AggregationParty {
                id,
                value: 0,
                masks_to_apply: HashMap::new(),
            })
            .collect();
        Self { parties }
    }

    /// Set each party's private value.
    pub fn set_value(&mut self, party_id: u32, value: i64) {
        if let Some(party) = self.parties.iter_mut().find(|p| p.id == party_id) {
            party.value = value;
        }
    }

    /// Establish pairwise masks between all parties. Each pair (i, j)
    /// generates a shared random mask: i adds it, j subtracts it.
    /// When summed, masks cancel.
    pub fn establish_masks(&mut self) {
        let n = self.parties.len();
        let mut rng = OsRng;
        for i in 0..n {
            for j in (i + 1)..n {
                // Use small masks to avoid i64 overflow
                let mask = (rng.next_u32() as i64) % 1000;
                let id_i = self.parties[i].id;
                let id_j = self.parties[j].id;
                self.parties[i].masks_to_apply.insert(id_j, mask);
                self.parties[j].masks_to_apply.insert(id_i, -mask);
            }
        }
    }

    /// Each party computes their masked value: v_i + sum(masks_to_apply).
    pub fn masked_values(&self) -> Vec<i64> {
        self.parties
            .iter()
            .map(|p| {
                let mask_sum: i64 = p.masks_to_apply.values().sum();
                p.value + mask_sum
            })
            .collect()
    }

    /// Aggregate masked values. The result equals the sum of all
    /// original values (masks cancel).
    pub fn aggregate(&self) -> i64 {
        self.masked_values().iter().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_preserved_with_masks() {
        let mut agg = SecureAggregation::new(3);
        agg.set_value(0, 10);
        agg.set_value(1, 20);
        agg.set_value(2, 30);
        agg.establish_masks();
        assert_eq!(agg.aggregate(), 60);
    }

    #[test]
    fn single_party() {
        let mut agg = SecureAggregation::new(1);
        agg.set_value(0, 42);
        agg.establish_masks();
        assert_eq!(agg.aggregate(), 42);
    }

    #[test]
    fn negative_values() {
        let mut agg = SecureAggregation::new(3);
        agg.set_value(0, -10);
        agg.set_value(1, 20);
        agg.set_value(2, -5);
        agg.establish_masks();
        assert_eq!(agg.aggregate(), 5);
    }

    #[test]
    fn many_parties() {
        let n = 10;
        let mut agg = SecureAggregation::new(n);
        let total: i64 = (1..=n as i64).sum();
        for i in 0..n {
            agg.set_value(i, (i + 1) as i64);
        }
        agg.establish_masks();
        assert_eq!(agg.aggregate(), total);
    }

    #[test]
    fn masked_values_hide_individuals() {
        let mut agg = SecureAggregation::new(2);
        agg.set_value(0, 100);
        agg.set_value(1, 200);
        agg.establish_masks();
        let masked = agg.masked_values();
        // Neither masked value should equal the original
        assert_ne!(masked[0], 100);
        assert_ne!(masked[1], 200);
    }

    #[test]
    fn zero_values() {
        let mut agg = SecureAggregation::new(3);
        agg.establish_masks();
        assert_eq!(agg.aggregate(), 0);
    }

    #[test]
    fn masks_symmetric() {
        let mut agg = SecureAggregation::new(2);
        agg.establish_masks();
        // mask from party 0 to 1 should be negation of 1 to 0
        let m01 = agg.parties[0].masks_to_apply.get(&1).copied().unwrap_or(0);
        let m10 = agg.parties[1].masks_to_apply.get(&0).copied().unwrap_or(0);
        assert_eq!(m01, -m10);
    }
}
