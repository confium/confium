//! Multi-round signing state machine.
//!
//! CMP20 and GG18 are multi-round protocols:
//!
//! - **CMP20**: Round 1 (nonce commitment) → Round 2 (MtA) → Round 3 (partial sig)
//! - **GG18**: Round 1 → Round 2 → Round 3 → Round 4
//!
//! The [`RoundCoordinator`] tracks which signers have responded in
//! each round and advances when the threshold is met.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Which round the protocol is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningRound {
    /// Round 1: nonce commitment.
    Round1,
    /// Round 2: MtA exchange (CMP20) or nonce reveal (FROST).
    Round2,
    /// Round 3: partial signature.
    Round3,
    /// Round 4: GG18 final combine.
    Round4,
    /// Protocol completed.
    Completed,
    /// Protocol aborted.
    Aborted,
}

impl SigningRound {
    /// Advance to the next round.
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Round1 => Some(Self::Round2),
            Self::Round2 => Some(Self::Round3),
            Self::Round3 => Some(Self::Round4),
            Self::Round4 => Some(Self::Completed),
            Self::Completed | Self::Aborted => None,
        }
    }

    /// 1-based round number.
    pub fn number(&self) -> u32 {
        match self {
            Self::Round1 => 1,
            Self::Round2 => 2,
            Self::Round3 => 3,
            Self::Round4 => 4,
            Self::Completed => 0,
            Self::Aborted => 0,
        }
    }

    /// Is this a terminal state?
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// State for a single round: which signers have responded.
#[derive(Debug, Clone)]
pub struct RoundState {
    /// The current round.
    pub round: SigningRound,
    /// Signers who have responded in this round.
    pub responded: HashSet<String>,
    /// When this round started.
    pub started_at: DateTime<Utc>,
    /// Round data collected so far (opaque bytes per signer).
    pub round_data: Vec<(String, Vec<u8>)>,
}

impl RoundState {
    fn new(round: SigningRound) -> Self {
        Self {
            round,
            responded: HashSet::new(),
            started_at: Utc::now(),
            round_data: Vec::new(),
        }
    }
}

/// Errors during round coordination.
#[derive(Debug, thiserror::Error)]
pub enum RoundError {
    /// Signer submitted in the wrong round.
    #[error("signer {signer} submitted in round {:?}, expected {:?}", actual, expected)]
    WrongRound {
        /// Signer ID.
        signer: String,
        /// Actual round.
        actual: SigningRound,
        /// Expected round.
        expected: SigningRound,
    },
    /// Duplicate submission in the same round.
    #[error("signer {0} already responded in this round")]
    DuplicateResponse(String),
    /// Protocol already completed.
    #[error("protocol already completed")]
    AlreadyCompleted,
    /// Protocol was aborted.
    #[error("protocol aborted: {0}")]
    Aborted(String),
    /// Not enough signers to advance.
    #[error("not enough responses: {have}/{need}")]
    InsufficientResponses { have: usize, need: usize },
}

/// The multi-round coordinator. Tracks protocol progress across
/// rounds and enforces the threshold requirement per round.
pub struct RoundCoordinator {
    threshold: u32,
    party_count: u32,
    current: RoundState,
    history: Vec<RoundState>,
}

impl RoundCoordinator {
    /// Create a new coordinator for a T-of-N protocol.
    pub fn new(threshold: u32, party_count: u32) -> Self {
        Self {
            threshold,
            party_count,
            current: RoundState::new(SigningRound::Round1),
            history: Vec::new(),
        }
    }

    /// Current round.
    pub fn current_round(&self) -> SigningRound {
        self.current.round
    }

    /// Number of signers who responded in the current round.
    pub fn response_count(&self) -> usize {
        self.current.responded.len()
    }

    /// Has this signer responded in the current round?
    pub fn has_responded(&self, signer_id: &str) -> bool {
        self.current.responded.contains(signer_id)
    }

    /// Submit a response for the current round. If the threshold is
    /// met, advances to the next round automatically.
    pub fn submit(
        &mut self,
        signer_id: &str,
        data: Vec<u8>,
    ) -> Result<Option<SigningRound>, RoundError> {
        if self.current.round.is_terminal() {
            return Err(RoundError::AlreadyCompleted);
        }
        if self.current.responded.contains(signer_id) {
            return Err(RoundError::DuplicateResponse(signer_id.into()));
        }
        self.current.responded.insert(signer_id.into());
        self.current.round_data.push((signer_id.into(), data));

        if self.current.responded.len() >= self.threshold as usize {
            let next = self
                .current
                .round
                .next()
                .ok_or(RoundError::AlreadyCompleted)?;
            let old = std::mem::replace(&mut self.current, RoundState::new(next));
            self.history.push(old);
            return Ok(Some(next));
        }
        Ok(None)
    }

    /// Collect all round data from a completed round.
    pub fn round_data(&self, round: SigningRound) -> Vec<(String, Vec<u8>)> {
        if round == self.current.round {
            return self.current.round_data.clone();
        }
        self.history
            .iter()
            .find(|s| s.round == round)
            .map(|s| s.round_data.clone())
            .unwrap_or_default()
    }

    /// Number of rounds completed.
    pub fn rounds_completed(&self) -> usize {
        self.history.len()
    }

    /// Abort the protocol.
    pub fn abort(&mut self, reason: &str) {
        self.current = RoundState::new(SigningRound::Aborted);
        let _ = reason;
    }

    /// Force-advance to the next round (admin/debug only). Does not
    /// check threshold.
    pub fn force_advance(&mut self) -> Option<SigningRound> {
        let next = self.current.round.next()?;
        let old = std::mem::replace(&mut self.current, RoundState::new(next));
        self.history.push(old);
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_round_1() {
        let rc = RoundCoordinator::new(2, 3);
        assert_eq!(rc.current_round(), SigningRound::Round1);
    }

    #[test]
    fn submit_advances_at_threshold() {
        let mut rc = RoundCoordinator::new(2, 3);
        assert!(rc.submit("alice", vec![1]).unwrap().is_none());
        assert_eq!(rc.current_round(), SigningRound::Round1);
        let advanced = rc.submit("bob", vec![2]).unwrap();
        assert_eq!(advanced, Some(SigningRound::Round2));
        assert_eq!(rc.current_round(), SigningRound::Round2);
    }

    #[test]
    fn duplicate_response_rejected() {
        let mut rc = RoundCoordinator::new(2, 3);
        rc.submit("alice", vec![1]).unwrap();
        assert!(matches!(
            rc.submit("alice", vec![2]),
            Err(RoundError::DuplicateResponse(_))
        ));
    }

    #[test]
    fn full_protocol_progression() {
        let mut rc = RoundCoordinator::new(2, 3);
        for round in [SigningRound::Round1, SigningRound::Round2, SigningRound::Round3] {
            assert_eq!(rc.current_round(), round);
            rc.submit("alice", vec![0xAA]).unwrap();
            rc.submit("bob", vec![0xBB]).unwrap();
        }
        assert_eq!(rc.current_round(), SigningRound::Round4);
        rc.submit("alice", vec![]).unwrap();
        rc.submit("bob", vec![]).unwrap();
        assert_eq!(rc.current_round(), SigningRound::Completed);
    }

    #[test]
    fn completed_rejects_submissions() {
        let mut rc = RoundCoordinator::new(1, 1);
        rc.submit("alice", vec![]).unwrap();
        assert_eq!(rc.current_round(), SigningRound::Round2);
        rc.force_advance();
        rc.force_advance();
        rc.force_advance();
        assert_eq!(rc.current_round(), SigningRound::Completed);
        assert!(rc.submit("alice", vec![]).is_err());
    }

    #[test]
    fn round_data_collected() {
        let mut rc = RoundCoordinator::new(2, 3);
        rc.submit("alice", vec![0x11]).unwrap();
        rc.submit("bob", vec![0x22]).unwrap();
        let r1_data = rc.round_data(SigningRound::Round1);
        assert_eq!(r1_data.len(), 2);
    }

    #[test]
    fn force_advance_skips_threshold() {
        let mut rc = RoundCoordinator::new(3, 5);
        rc.submit("alice", vec![]).unwrap();
        rc.force_advance();
        assert_eq!(rc.current_round(), SigningRound::Round2);
    }

    #[test]
    fn rounds_completed_tracks_history() {
        let mut rc = RoundCoordinator::new(2, 3);
        assert_eq!(rc.rounds_completed(), 0);
        rc.submit("a", vec![]).unwrap();
        rc.submit("b", vec![]).unwrap();
        assert_eq!(rc.rounds_completed(), 1);
    }

    #[test]
    fn abort_sets_terminal_state() {
        let mut rc = RoundCoordinator::new(2, 3);
        rc.abort("test failure");
        assert_eq!(rc.current_round(), SigningRound::Aborted);
        assert!(rc.current_round().is_terminal());
    }

    #[test]
    fn round_number_correct() {
        assert_eq!(SigningRound::Round1.number(), 1);
        assert_eq!(SigningRound::Round4.number(), 4);
        assert_eq!(SigningRound::Completed.number(), 0);
    }

    #[test]
    fn terminal_states_have_no_next() {
        assert!(SigningRound::Completed.next().is_none());
        assert!(SigningRound::Aborted.next().is_none());
    }

    #[test]
    fn has_responded_tracks_signers() {
        let mut rc = RoundCoordinator::new(2, 3);
        rc.submit("alice", vec![]).unwrap();
        assert!(rc.has_responded("alice"));
        assert!(!rc.has_responded("bob"));
    }
}
