//! Proactive refresh (Herzberg et al. 1995 pattern).
//!
//! Periodic share refresh invalidates previously-compromised shares
//! without changing the public key. Each party generates a random
//! polynomial with f_i(0) = 0; sum of all contributions at any point
//! is zero, so adding refresh contributions to existing shares does
//! not change the aggregate secret.

use crate::reshare::lagrange::FieldElement;
use serde::{Deserialize, Serialize};

/// Parameters for a refresh round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshParams {
    /// Algorithm.
    pub algorithm: String,
    /// Number of parties.
    pub num_parties: u32,
    /// Threshold T (refresh preserves threshold).
    pub threshold: u32,
}

/// A refresh contribution from party `i` to party `j`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshContribution {
    /// Source party index.
    pub from_party: u32,
    /// Destination party index.
    pub to_party: u32,
    /// Refresh bytes (the value f_i(j) where f_i is party i's random polynomial).
    pub bytes: Vec<u8>,
}

/// Compute the new share given an old share and a set of refresh contributions.
///
/// new_share[j] = old_share[j] + sum_i(contribution[i->j])
///
/// For real algorithms, this addition happens in the field of the curve
/// or group. This function provides the byte-level skeleton; algorithm
/// crates provide field arithmetic.
pub fn apply_refresh(
    old_share: &FieldElement,
    contributions: &[RefreshContribution],
) -> FieldElement {
    // Mock: XOR bytes together (real impl uses field addition).
    let mut new_bytes = old_share.0.clone();
    for c in contributions {
        for (i, b) in c.bytes.iter().enumerate() {
            if i < new_bytes.len() {
                new_bytes[i] ^= b;
            }
        }
    }
    FieldElement::new(new_bytes)
}

/// Verify that a refresh round preserves the aggregate secret.
///
/// For correct refresh polynomials: sum_i f_i(0) == 0 for all parties.
/// This check validates that invariant.
pub fn verify_refresh_preserves_aggregate(
    party_zero_contributions: &[RefreshContribution],
) -> bool {
    // Mock verification: sum of bytes mod 256 should be zero for any party's
    // contribution evaluated at 0 (i.e., f_i(0) = 0 means all bytes are zero
    // when summed appropriately). For real algorithms this uses field math.
    let mut sum = [0u8; 32];
    for c in party_zero_contributions {
        for (i, b) in c.bytes.iter().enumerate() {
            if i < sum.len() {
                sum[i] = sum[i].wrapping_add(*b);
            }
        }
    }
    sum.iter().all(|b| *b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_changes_share() {
        let old = FieldElement::new(vec![0u8; 32]);
        let contribs = vec![RefreshContribution {
            from_party: 0,
            to_party: 0,
            bytes: vec![0xFF; 32],
        }];
        let new = apply_refresh(&old, &contribs);
        assert_ne!(new.0, old.0);
    }

    #[test]
    fn refresh_preserves_secret_when_balanced() {
        let contribs = vec![
            RefreshContribution {
                from_party: 0,
                to_party: 0,
                bytes: vec![0x80; 32],
            },
            RefreshContribution {
                from_party: 1,
                to_party: 0,
                bytes: vec![0x80; 32],
            },
        ];
        // 0x80 + 0x80 = 0x00 (mod 256) — mock "preservation"
        assert!(verify_refresh_preserves_aggregate(&contribs));
    }
}
