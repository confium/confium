//! Proactive share refresh coordinator.
//!
//! Herzberg proactive refresh rotates shares without changing the
//! joint public key. The coordinator orchestrates:
//! 1. Generate refresh shares (random polynomial at x=0 = 0)
//! 2. Distribute to all parties
//! 3. Each party sums their received refresh shares
//! 4. Each party adds the sum to their existing share

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A refresh contribution from one party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshContribution {
    /// Party generating this contribution.
    pub from_party: u32,
    /// Shares for each recipient party.
    pub refresh_shares: HashMap<u32, Vec<u8>>,
}

/// A refresh session.
#[derive(Debug)]
pub struct RefreshSession {
    pub session_id: String,
    pub threshold: u32,
    pub party_count: u32,
    pub contributions: HashMap<u32, RefreshContribution>,
}

impl RefreshSession {
    pub fn new(session_id: &str, threshold: u32, party_count: u32) -> Self {
        Self {
            session_id: session_id.into(),
            threshold,
            party_count,
            contributions: HashMap::new(),
        }
    }

    /// Submit a refresh contribution from a party.
    pub fn submit_contribution(&mut self, contrib: RefreshContribution) -> Result<(), String> {
        if contrib.from_party == 0 || contrib.from_party > self.party_count {
            return Err(format!("invalid from_party: {}", contrib.from_party));
        }
        if self.contributions.contains_key(&contrib.from_party) {
            return Err(format!("party {} already contributed", contrib.from_party));
        }
        self.contributions.insert(contrib.from_party, contrib);
        Ok(())
    }

    /// Check if all parties have contributed.
    pub fn is_complete(&self) -> bool {
        self.contributions.len() == self.party_count as usize
    }

    /// Get the aggregate refresh for a specific party.
    /// Returns the XOR of all refresh shares addressed to that party.
    pub fn aggregate_for_party(&self, party_idx: u32) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut result: Option<Vec<u8>> = None;
        for contrib in self.contributions.values() {
            if let Some(share) = contrib.refresh_shares.get(&party_idx) {
                result = Some(match result {
                    None => share.clone(),
                    Some(mut existing) => {
                        let len = existing.len().max(share.len());
                        existing.resize(len, 0);
                        for (i, &b) in share.iter().enumerate() {
                            existing[i] ^= b;
                        }
                        existing
                    }
                });
            }
        }
        result
    }

    /// Number of contributions received.
    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// List parties that haven't contributed yet.
    pub fn missing_parties(&self) -> Vec<u32> {
        (1..=self.party_count)
            .filter(|i| !self.contributions.contains_key(i))
            .collect()
    }
}

/// Generate a refresh contribution from one party.
/// Each share is random; the constraint is that the polynomial
/// evaluates to 0 at x=0 (so the joint key doesn't change).
pub fn generate_contribution(
    from_party: u32,
    party_count: u32,
    share_size: usize,
) -> RefreshContribution {
    use rand_core::{OsRng, RngCore};
    let mut refresh_shares = HashMap::new();
    let mut remaining = vec![0u8; share_size];

    // Generate random shares for parties 1..N-1
    for p in 1..party_count {
        let mut share = vec![0u8; share_size];
        OsRng.fill_bytes(&mut share);
        for (i, &b) in share.iter().enumerate() {
            remaining[i] ^= b;
        }
        refresh_shares.insert(p, share);
    }

    // Party N gets the XOR of all others (so sum = 0)
    refresh_shares.insert(party_count, remaining);

    RefreshContribution {
        from_party,
        refresh_shares,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_empty() {
        let session = RefreshSession::new("r1", 2, 3);
        assert_eq!(session.contribution_count(), 0);
        assert!(!session.is_complete());
    }

    #[test]
    fn submit_contribution() {
        let mut session = RefreshSession::new("r1", 2, 3);
        let contrib = RefreshContribution {
            from_party: 1,
            refresh_shares: HashMap::new(),
        };
        session.submit_contribution(contrib).unwrap();
        assert_eq!(session.contribution_count(), 1);
    }

    #[test]
    fn complete_when_all_contributed() {
        let mut session = RefreshSession::new("r1", 2, 3);
        for p in 1..=3 {
            session
                .submit_contribution(RefreshContribution {
                    from_party: p,
                    refresh_shares: HashMap::new(),
                })
                .unwrap();
        }
        assert!(session.is_complete());
    }

    #[test]
    fn duplicate_contribution_rejected() {
        let mut session = RefreshSession::new("r1", 2, 3);
        let contrib = RefreshContribution {
            from_party: 1,
            refresh_shares: HashMap::new(),
        };
        session.submit_contribution(contrib).unwrap();
        let contrib2 = RefreshContribution {
            from_party: 1,
            refresh_shares: HashMap::new(),
        };
        assert!(session.submit_contribution(contrib2).is_err());
    }

    #[test]
    fn aggregate_requires_complete() {
        let session = RefreshSession::new("r1", 2, 3);
        assert!(session.aggregate_for_party(1).is_none());
    }

    #[test]
    fn aggregate_xors_shares() {
        let mut session = RefreshSession::new("r1", 2, 2);
        let mut shares1 = HashMap::new();
        shares1.insert(1u32, vec![0xFF]);
        shares1.insert(2u32, vec![0x0F]);
        session
            .submit_contribution(RefreshContribution {
                from_party: 1,
                refresh_shares: shares1,
            })
            .unwrap();

        let mut shares2 = HashMap::new();
        shares2.insert(1u32, vec![0xAA]);
        shares2.insert(2u32, vec![0x55]);
        session
            .submit_contribution(RefreshContribution {
                from_party: 2,
                refresh_shares: shares2,
            })
            .unwrap();

        let agg1 = session.aggregate_for_party(1).unwrap();
        // 0xFF XOR 0xAA = 0x55
        assert_eq!(agg1, vec![0x55]);
    }

    #[test]
    fn generate_contribution_shares_sum_to_zero() {
        let contrib = generate_contribution(1, 3, 32);
        // XOR all shares should give zero
        let mut xored = vec![0u8; 32];
        for share in contrib.refresh_shares.values() {
            for (i, &b) in share.iter().enumerate() {
                xored[i] ^= b;
            }
        }
        assert_eq!(xored, vec![0u8; 32]);
    }

    #[test]
    fn missing_parties_lists_gaps() {
        let mut session = RefreshSession::new("r1", 2, 5);
        session
            .submit_contribution(RefreshContribution {
                from_party: 1,
                refresh_shares: HashMap::new(),
            })
            .unwrap();
        session
            .submit_contribution(RefreshContribution {
                from_party: 3,
                refresh_shares: HashMap::new(),
            })
            .unwrap();
        let missing = session.missing_parties();
        assert_eq!(missing, vec![2, 4, 5]);
    }
}
