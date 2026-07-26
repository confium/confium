//! Re-sharing session parameters and state.

use crate::reshare::lagrange::FieldElement;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Old committee member with their share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OldCommitteeMember {
    /// Party index in old committee.
    pub party_index: u32,
    /// Share bytes (kept encrypted at rest by caller).
    pub share: FieldElement,
}

/// New committee member identifier (public; no share yet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewCommitteeMember {
    /// Party index in new committee.
    pub party_index: u32,
    /// Public identity key (for encrypting new shares to this party).
    pub identity_public_key: Vec<u8>,
}

/// Parameters for a re-sharing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareParams {
    /// Algorithm (must match old committee's).
    pub algorithm: String,
    /// Old committee members.
    pub old_committee: Vec<OldCommitteeMember>,
    /// Old threshold T.
    pub old_threshold: u32,
    /// New committee members.
    pub new_committee: Vec<NewCommitteeMember>,
    /// New threshold T'.
    pub new_threshold: u32,
}

/// State of a re-sharing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReshareState {
    /// Session created.
    Pending,
    /// Old shares collected, contributions computed.
    ContributionsComputed,
    /// New shares distributed to new committee members.
    Distributed,
    /// New committee verified by test signature.
    Verified,
    /// Aborted.
    Aborted,
}

/// Re-sharing session.
pub struct ReshareSession {
    params: ReshareParams,
    state: ReshareState,
    new_shares: Vec<(u32, FieldElement)>,
    created_at: DateTime<Utc>,
}

/// Re-sharing errors.
#[derive(Debug, thiserror::Error)]
pub enum ReshareError {
    /// Insufficient old shares.
    #[error("insufficient old shares: have {have}, need {need}")]
    InsufficientOldShares {
        /// Count received.
        have: usize,
        /// Threshold required.
        need: u32,
    },
    /// Invalid state for operation.
    #[error("invalid state: current {current:?}")]
    InvalidState {
        /// Current state.
        current: ReshareState,
    },
    /// Committee mismatch.
    #[error("committee mismatch")]
    CommitteeMismatch,
}

impl ReshareSession {
    /// Create a new re-sharing session.
    pub fn new(params: ReshareParams) -> Self {
        Self {
            params,
            state: ReshareState::Pending,
            new_shares: Vec::new(),
            created_at: Utc::now(),
        }
    }

    /// Current state.
    pub fn state(&self) -> ReshareState {
        self.state
    }

    /// Mark contributions as computed (after T-old shares are processed).
    pub fn mark_contributions_computed(&mut self) -> Result<(), ReshareError> {
        if self.state != ReshareState::Pending {
            return Err(ReshareError::InvalidState {
                current: self.state,
            });
        }
        if (self.params.old_committee.len() as u32) < self.params.old_threshold {
            return Err(ReshareError::InsufficientOldShares {
                have: self.params.old_committee.len(),
                need: self.params.old_threshold,
            });
        }
        self.state = ReshareState::ContributionsComputed;
        Ok(())
    }

    /// Mark shares distributed to new committee.
    pub fn mark_distributed(&mut self) -> Result<(), ReshareError> {
        if self.state != ReshareState::ContributionsComputed {
            return Err(ReshareError::InvalidState {
                current: self.state,
            });
        }
        self.state = ReshareState::Distributed;
        Ok(())
    }

    /// Mark new committee verified (test signature validates under same public key).
    pub fn mark_verified(&mut self) -> Result<(), ReshareError> {
        if self.state != ReshareState::Distributed {
            return Err(ReshareError::InvalidState {
                current: self.state,
            });
        }
        self.state = ReshareState::Verified;
        Ok(())
    }

    /// When the session was created.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Reference to params.
    pub fn params(&self) -> &ReshareParams {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_params() -> ReshareParams {
        ReshareParams {
            algorithm: "FROST-ed25519".into(),
            old_committee: vec![
                OldCommitteeMember {
                    party_index: 0,
                    share: FieldElement::new(vec![1u8; 32]),
                },
                OldCommitteeMember {
                    party_index: 1,
                    share: FieldElement::new(vec![2u8; 32]),
                },
                OldCommitteeMember {
                    party_index: 2,
                    share: FieldElement::new(vec![3u8; 32]),
                },
            ],
            old_threshold: 2,
            new_committee: vec![
                NewCommitteeMember {
                    party_index: 0,
                    identity_public_key: vec![0u8; 32],
                },
                NewCommitteeMember {
                    party_index: 1,
                    identity_public_key: vec![1u8; 32],
                },
            ],
            new_threshold: 2,
        }
    }

    #[test]
    fn full_lifecycle() {
        let mut session = ReshareSession::new(sample_params());
        assert_eq!(session.state(), ReshareState::Pending);
        session.mark_contributions_computed().unwrap();
        assert_eq!(session.state(), ReshareState::ContributionsComputed);
        session.mark_distributed().unwrap();
        assert_eq!(session.state(), ReshareState::Distributed);
        session.mark_verified().unwrap();
        assert_eq!(session.state(), ReshareState::Verified);
    }

    #[test]
    fn insufficient_old_shares_fails() {
        let mut params = sample_params();
        params.old_threshold = 5;
        let mut session = ReshareSession::new(params);
        let result = session.mark_contributions_computed();
        assert!(matches!(result, Err(ReshareError::InsufficientOldShares { .. })));
    }

    #[test]
    fn wrong_state_fails() {
        let mut session = ReshareSession::new(sample_params());
        // Try to skip the contributions step
        let result = session.mark_distributed();
        assert!(matches!(result, Err(ReshareError::InvalidState { .. })));
    }
}
