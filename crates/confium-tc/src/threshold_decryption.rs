//! Threshold decryption coordinator.
//!
//! Coordinates ElGamal-style threshold decryption: collect decryption
//! shares from T parties and combine them into the full plaintext.

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A decryption share from one party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    pub party_idx: u32,
    /// The partial decryption value.
    pub share: Vec<u8>,
}

/// A threshold decryption session.
#[derive(Debug)]
pub struct DecryptionSession {
    pub session_id: String,
    pub threshold: u32,
    pub party_count: u32,
    pub ciphertext: Vec<u8>,
    pub shares: HashMap<u32, DecryptionShare>,
}

impl DecryptionSession {
    pub fn new(session_id: &str, threshold: u32, party_count: u32, ciphertext: &[u8]) -> Self {
        Self {
            session_id: session_id.into(),
            threshold,
            party_count,
            ciphertext: ciphertext.to_vec(),
            shares: HashMap::new(),
        }
    }

    /// Submit a decryption share.
    pub fn submit_share(&mut self, share: DecryptionShare) -> Result<(), String> {
        if share.party_idx == 0 || share.party_idx > self.party_count {
            return Err(format!("invalid party_idx: {}", share.party_idx));
        }
        if self.shares.contains_key(&share.party_idx) {
            return Err(format!("party {} already submitted", share.party_idx));
        }
        self.shares.insert(share.party_idx, share);
        Ok(())
    }

    /// Check if enough shares have been collected.
    pub fn is_ready(&self) -> bool {
        self.shares.len() >= self.threshold as usize
    }

    /// Number of shares collected.
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// Collect the shares in party-index order for combination.
    pub fn ordered_shares(&self) -> Vec<&DecryptionShare> {
        let mut shares: Vec<&DecryptionShare> = self.shares.values().collect();
        shares.sort_by_key(|s| s.party_idx);
        shares
    }

    /// Missing party indices (those that haven't submitted).
    pub fn missing_parties(&self) -> Vec<u32> {
        (1..=self.party_count)
            .filter(|i| !self.shares.contains_key(i))
            .collect()
    }
}

/// Errors during threshold decryption.
#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    #[error("insufficient shares: {have}/{need}")]
    InsufficientShares { have: usize, need: u32 },
    #[error("combination failed: {0}")]
    CombinationFailed(String),
}

/// Combine decryption shares using Lagrange interpolation.
/// In a real implementation, this would use the group operation
/// (e.g., EC point addition weighted by Lagrange coefficients).
/// Here, we XOR-combine for the mock case.
pub fn combine_shares(
    session: &DecryptionSession,
) -> Result<Vec<u8>, DecryptionError> {
    if !session.is_ready() {
        return Err(DecryptionError::InsufficientShares {
            have: session.share_count(),
            need: session.threshold,
        });
    }

    let shares = session.ordered_shares();
    let max_len = shares.iter().map(|s| s.share.len()).max().unwrap_or(0);
    let mut result = vec![0u8; max_len];
    for share in &shares {
        for (i, &b) in share.share.iter().enumerate() {
            result[i] ^= b;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_share(party_idx: u32, byte: u8) -> DecryptionShare {
        DecryptionShare {
            party_idx,
            share: vec![byte; 32],
        }
    }

    #[test]
    fn new_session_empty() {
        let session = DecryptionSession::new("s1", 2, 3, &[0; 32]);
        assert_eq!(session.share_count(), 0);
        assert!(!session.is_ready());
    }

    #[test]
    fn submit_share_increments_count() {
        let mut session = DecryptionSession::new("s1", 2, 3, &[0; 32]);
        session.submit_share(make_share(1, 0xAA)).unwrap();
        assert_eq!(session.share_count(), 1);
    }

    #[test]
    fn ready_at_threshold() {
        let mut session = DecryptionSession::new("s1", 2, 3, &[0; 32]);
        session.submit_share(make_share(1, 0xAA)).unwrap();
        assert!(!session.is_ready());
        session.submit_share(make_share(2, 0xBB)).unwrap();
        assert!(session.is_ready());
    }

    #[test]
    fn duplicate_submission_rejected() {
        let mut session = DecryptionSession::new("s1", 2, 3, &[0; 32]);
        session.submit_share(make_share(1, 0xAA)).unwrap();
        assert!(session.submit_share(make_share(1, 0xBB)).is_err());
    }

    #[test]
    fn invalid_party_idx_rejected() {
        let mut session = DecryptionSession::new("s1", 2, 3, &[0; 32]);
        assert!(session.submit_share(make_share(0, 0xAA)).is_err());
        assert!(session.submit_share(make_share(4, 0xAA)).is_err());
    }

    #[test]
    fn combine_requires_threshold() {
        let session = DecryptionSession::new("s1", 3, 5, &[0; 32]);
        assert!(combine_shares(&session).is_err());
    }

    #[test]
    fn combine_xors_shares() {
        let mut session = DecryptionSession::new("s1", 2, 3, &[0; 32]);
        session.submit_share(make_share(1, 0xFF)).unwrap();
        session.submit_share(make_share(2, 0x0F)).unwrap();
        let result = combine_shares(&session).unwrap();
        // XOR of 0xFF and 0x0F = 0xF0
        assert_eq!(result, vec![0xF0; 32]);
    }

    #[test]
    fn ordered_shares_sorted() {
        let mut session = DecryptionSession::new("s1", 3, 5, &[0; 32]);
        session.submit_share(make_share(3, 0x33)).unwrap();
        session.submit_share(make_share(1, 0x11)).unwrap();
        session.submit_share(make_share(2, 0x22)).unwrap();
        let ordered = session.ordered_shares();
        assert_eq!(ordered[0].party_idx, 1);
        assert_eq!(ordered[1].party_idx, 2);
        assert_eq!(ordered[2].party_idx, 3);
    }

    #[test]
    fn missing_parties_lists_gaps() {
        let mut session = DecryptionSession::new("s1", 3, 5, &[0; 32]);
        session.submit_share(make_share(1, 0xAA)).unwrap();
        session.submit_share(make_share(3, 0xCC)).unwrap();
        let missing = session.missing_parties();
        assert_eq!(missing, vec![2, 4, 5]);
    }
}
