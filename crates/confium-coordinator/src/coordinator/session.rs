//! Coordinator session state machine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Unique session identifier.
pub type SessionId = String;

/// Quorum identifier.
pub type QuorumId = String;

/// Signer identifier (typically their actor ID).
pub type SignerId = String;

/// Session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Session created; awaiting signer commitments.
    Pending,
    /// T commitments received; awaiting shares.
    CommitmentsCollected,
    /// T shares received; signature aggregated.
    Completed,
    /// Unlock window elapsed before T commitments/shares.
    Expired,
    /// Aborted due to error or admin action.
    Aborted,
}

/// A signing session request from an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    /// Quorum authorizing this signature.
    pub quorum_id: QuorumId,
    /// Threshold scheme (e.g., "FROST-ed25519").
    pub scheme: String,
    /// Message to be signed (digest bytes).
    pub message: Vec<u8>,
    /// Threshold T.
    pub threshold: u32,
    /// Total parties N.
    pub num_parties: u32,
    /// Unlock window in minutes.
    pub unlock_window_minutes: u32,
    /// Requesting actor.
    pub requested_by: SignerId,
}

/// A commitment submitted by a signer (round 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    /// Submitting signer.
    pub signer_id: SignerId,
    /// Commitment bytes (algorithm-specific).
    pub bytes: Vec<u8>,
    /// Signer's identity signature on the commitment (non-repudiation).
    pub signer_signature: Vec<u8>,
    /// When the commitment was submitted.
    pub submitted_at: DateTime<Utc>,
}

/// A share submitted by a signer (round 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Submitting signer.
    pub signer_id: SignerId,
    /// Share bytes (algorithm-specific).
    pub bytes: Vec<u8>,
    /// Signer's identity signature on the share.
    pub signer_signature: Vec<u8>,
    /// When the share was submitted.
    pub submitted_at: DateTime<Utc>,
}

/// The final aggregated signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedSignature {
    /// Signature bytes.
    pub bytes: Vec<u8>,
    /// Algorithm identifier.
    pub algorithm: String,
    /// When aggregation completed.
    pub completed_at: DateTime<Utc>,
    /// List of signers who contributed.
    pub contributing_signers: Vec<SignerId>,
}

/// Session errors.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Session not found.
    #[error("session not found: {0}")]
    NotFound(SessionId),
    /// Session in wrong state.
    #[error("session {session_id} in state {current_state:?}, expected {expected}")]
    InvalidState {
        /// Session ID.
        session_id: SessionId,
        /// Current state.
        current_state: SessionState,
        /// Expected state description.
        expected: &'static str,
    },
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Count received.
        have: usize,
        /// Threshold.
        need: u32,
    },
    /// Signer already submitted.
    #[error("signer {signer} already submitted to session {session}")]
    DuplicateSubmission {
        /// Signer ID.
        signer: SignerId,
        /// Session ID.
        session: SessionId,
    },
    /// Unlock window expired.
    #[error("session {0} unlock window expired")]
    Expired(SessionId),
    /// Unauthorized signer.
    #[error("signer {0} not authorized for this quorum")]
    UnauthorizedSigner(SignerId),
    /// Threshold signing engine failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}
