//! Coordinator service — owns sessions, dispatches commitments/shares.

use std::collections::HashMap;

use crate::coordinator::audit::{AuditEvent, AuditLog};
use crate::coordinator::session::{
    AggregatedSignature, Commitment, SessionError, SessionId, SessionRequest, SessionState, Share,
};
use chrono::{DateTime, Duration, Utc};

/// A single signing session managed by the coordinator.
pub struct CoordinatorSession {
    pub(crate) id: SessionId,
    pub(crate) request: SessionRequest,
    pub(crate) state: SessionState,
    pub(crate) commitments: Vec<Commitment>,
    pub(crate) shares: Vec<Share>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) completed_at: Option<DateTime<Utc>>,
}

impl CoordinatorSession {
    /// When the session expires (created + unlock window).
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.created_at + Duration::minutes(self.request.unlock_window_minutes as i64)
    }

    /// Is the session still within its unlock window?
    pub fn is_unlocked(&self, now: DateTime<Utc>) -> bool {
        now <= self.expires_at()
    }

    /// Threshold T.
    pub fn threshold(&self) -> u32 {
        self.request.threshold
    }
}

/// The coordinator service.
pub struct Coordinator {
    sessions: HashMap<SessionId, CoordinatorSession>,
    audit_log: AuditLog,
    next_id: u64,
}

impl Coordinator {
    /// Construct a new empty coordinator.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            audit_log: AuditLog::new(),
            next_id: 0,
        }
    }

    /// Create a new session.
    pub fn create_session(&mut self, request: SessionRequest) -> Result<SessionId, SessionError> {
        let id = format!("session-{}", self.next_id);
        self.next_id += 1;
        let session = CoordinatorSession {
            id: id.clone(),
            request,
            state: SessionState::Pending,
            commitments: Vec::new(),
            shares: Vec::new(),
            created_at: Utc::now(),
            completed_at: None,
        };
        self.audit_log.append(
            id.clone(),
            AuditEvent::SessionCreated {
                requested_by: session.request.requested_by.clone(),
                quorum_id: session.request.quorum_id.clone(),
            },
        );
        self.sessions.insert(id.clone(), session);
        Ok(id)
    }

    /// Submit a commitment to a session.
    pub fn submit_commitment(
        &mut self,
        session_id: &str,
        commitment: Commitment,
    ) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.into()))?;

        if !session.is_unlocked(Utc::now()) {
            session.state = SessionState::Expired;
            self.audit_log.append(session_id.to_string(), AuditEvent::Expired);
            return Err(SessionError::Expired(session_id.into()));
        }

        if session.state != SessionState::Pending {
            return Err(SessionError::InvalidState {
                session_id: session_id.into(),
                current_state: session.state,
                expected: "pending",
            });
        }

        if session
            .commitments
            .iter()
            .any(|c| c.signer_id == commitment.signer_id)
        {
            return Err(SessionError::DuplicateSubmission {
                signer: commitment.signer_id.clone(),
                session: session_id.into(),
            });
        }

        self.audit_log.append(
            session_id.to_string(),
            AuditEvent::CommitmentReceived {
                signer: commitment.signer_id.clone(),
            },
        );
        session.commitments.push(commitment);

        if session.commitments.len() >= session.threshold() as usize {
            session.state = SessionState::CommitmentsCollected;
        }
        Ok(())
    }

    /// Submit a share to a session.
    pub fn submit_share(
        &mut self,
        session_id: &str,
        share: Share,
    ) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.into()))?;

        if !session.is_unlocked(Utc::now()) {
            session.state = SessionState::Expired;
            self.audit_log.append(session_id.to_string(), AuditEvent::Expired);
            return Err(SessionError::Expired(session_id.into()));
        }

        if session.state != SessionState::CommitmentsCollected
            && session.state != SessionState::Pending
        {
            return Err(SessionError::InvalidState {
                session_id: session_id.into(),
                current_state: session.state,
                expected: "commitments_collected or pending",
            });
        }

        if session.shares.iter().any(|s| s.signer_id == share.signer_id) {
            return Err(SessionError::DuplicateSubmission {
                signer: share.signer_id.clone(),
                session: session_id.into(),
            });
        }

        self.audit_log.append(
            session_id.to_string(),
            AuditEvent::ShareReceived {
                signer: share.signer_id.clone(),
            },
        );
        session.shares.push(share);

        Ok(())
    }

    /// Aggregate shares into the final signature.
    pub fn aggregate(&mut self, session_id: &str) -> Result<AggregatedSignature, SessionError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.into()))?;

        if session.shares.len() < session.threshold() as usize {
            return Err(SessionError::ThresholdNotMet {
                have: session.shares.len(),
                need: session.threshold(),
            });
        }

        // Mock aggregation: XOR all shares together.
        let mut aggregated = vec![0u8; 64];
        for share in &session.shares {
            for (i, b) in share.bytes.iter().take(64).enumerate() {
                aggregated[i] ^= b;
            }
        }

        let contributing: Vec<String> =
            session.shares.iter().map(|s| s.signer_id.clone()).collect();

        let sig = AggregatedSignature {
            bytes: aggregated,
            algorithm: session.request.scheme.clone(),
            completed_at: Utc::now(),
            contributing_signers: contributing,
        };

        session.state = SessionState::Completed;
        session.completed_at = Some(Utc::now());
        self.audit_log.append(session_id.to_string(), AuditEvent::Aggregated);
        Ok(sig)
    }

    /// Query session state.
    pub fn session_state(&self, session_id: &str) -> Option<SessionState> {
        self.sessions.get(session_id).map(|s| s.state)
    }

    /// Reference to audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Count of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get the threshold for a session.
    pub fn session_threshold(&self, session_id: &str) -> Option<u32> {
        self.sessions.get(session_id).map(|s| s.threshold())
    }

    /// Get the number of shares submitted for a session.
    pub fn session_share_count(&self, session_id: &str) -> Option<usize> {
        self.sessions.get(session_id).map(|s| s.shares.len())
    }

    /// Get the number of commitments submitted for a session.
    pub fn session_commitment_count(&self, session_id: &str) -> Option<usize> {
        self.sessions.get(session_id).map(|s| s.commitments.len())
    }

    /// Get the message for a session.
    pub fn session_message(&self, session_id: &str) -> Option<&[u8]> {
        self.sessions.get(session_id).map(|s| s.request.message.as_slice())
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> SessionRequest {
        SessionRequest {
            quorum_id: "test-quorum".into(),
            scheme: "FROST-ed25519".into(),
            message: vec![0u8; 32],
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: 240,
            requested_by: "test-app".into(),
        }
    }

    fn commitment_for(signer: &str) -> Commitment {
        Commitment {
            signer_id: signer.into(),
            bytes: vec![1u8; 32],
            signer_signature: vec![0u8; 64],
            submitted_at: Utc::now(),
        }
    }

    fn share_for(signer: &str) -> Share {
        Share {
            signer_id: signer.into(),
            bytes: vec![2u8; 64],
            signer_signature: vec![0u8; 64],
            submitted_at: Utc::now(),
        }
    }

    #[test]
    fn full_session_lifecycle() {
        let mut coord = Coordinator::new();
        let id = coord.create_session(sample_request()).unwrap();
        assert_eq!(coord.session_state(&id), Some(SessionState::Pending));

        coord.submit_commitment(&id, commitment_for("alice")).unwrap();
        coord.submit_commitment(&id, commitment_for("bob")).unwrap();
        assert_eq!(coord.session_state(&id), Some(SessionState::CommitmentsCollected));

        coord.submit_share(&id, share_for("alice")).unwrap();
        coord.submit_share(&id, share_for("bob")).unwrap();

        let sig = coord.aggregate(&id).unwrap();
        assert!(!sig.bytes.is_empty());
        assert_eq!(sig.contributing_signers, vec!["alice", "bob"]);
        assert_eq!(coord.session_state(&id), Some(SessionState::Completed));
    }

    #[test]
    fn duplicate_commitment_rejected() {
        let mut coord = Coordinator::new();
        let id = coord.create_session(sample_request()).unwrap();
        coord.submit_commitment(&id, commitment_for("alice")).unwrap();
        let result = coord.submit_commitment(&id, commitment_for("alice"));
        assert!(matches!(result, Err(SessionError::DuplicateSubmission { .. })));
    }

    #[test]
    fn aggregate_below_threshold_fails() {
        let mut coord = Coordinator::new();
        let id = coord.create_session(sample_request()).unwrap();
        let result = coord.aggregate(&id);
        assert!(matches!(result, Err(SessionError::ThresholdNotMet { .. })));
    }

    #[test]
    fn audit_log_records_full_lifecycle() {
        let mut coord = Coordinator::new();
        let id = coord.create_session(sample_request()).unwrap();
        coord.submit_commitment(&id, commitment_for("alice")).unwrap();
        coord.submit_commitment(&id, commitment_for("bob")).unwrap();
        coord.submit_share(&id, share_for("alice")).unwrap();
        coord.submit_share(&id, share_for("bob")).unwrap();
        coord.aggregate(&id).unwrap();

        let entries = coord.audit_log().entries_for(&id);
        assert_eq!(entries.len(), 6); // created + 2 commitments + 2 shares + aggregated
    }

    #[test]
    fn unknown_session_returns_error() {
        let mut coord = Coordinator::new();
        let result = coord.submit_commitment("nonexistent", commitment_for("x"));
        assert!(matches!(result, Err(SessionError::NotFound(_))));
    }
}
