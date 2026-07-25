//! Threshold KEM decapsulation session.
//!
//! State machine parallel to `confium-tc::Session` but for decryption.
//! Each party holds a share; T-of-N collaborate via the coordinator to
//! decapsulate a shared secret that can then AEAD-decrypt the ciphertext.

use crate::encapsulate::{EncapsulatedKey, EncapsulateError};
use crate::share::ThresholdShare;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Parameters for a decapsulation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemSessionParams {
    /// Algorithm identifier (must match encapsulated key).
    pub algorithm: String,
    /// Quorum identifier (which quorum's shares are being used).
    pub quorum_id: String,
    /// Threshold T.
    pub threshold: u32,
    /// Total number of parties N.
    pub num_parties: u32,
    /// This party's index (0-based).
    pub this_party_idx: u32,
    /// The encapsulated key to decapsulate.
    pub encapsulated_key: EncapsulatedKey,
}

/// State of a decapsulation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KemSessionState {
    /// Session created, awaiting round 1 messages.
    Pending,
    /// Round 1 complete, awaiting round 2 messages.
    Round1Complete,
    /// Decapsulation complete; shared secret available.
    Completed,
    /// Session expired before completion.
    Expired,
    /// Session aborted due to error.
    Aborted,
}

/// A decapsulation session.
pub struct KemSession {
    params: KemSessionParams,
    state: KemSessionState,
    local_share: Option<ThresholdShare>,
    partial_decryptions: Vec<PartialDecryption>,
    result: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
}

/// A single party's partial decryption contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// Contributing party index.
    pub party_index: u32,
    /// Partial decryption bytes (algorithm-specific).
    pub bytes: Vec<u8>,
}

/// Errors during decapsulation.
#[derive(Debug, thiserror::Error)]
pub enum KemError {
    /// Wrap encapsulate-side errors.
    #[error("encapsulate error: {0}")]
    Encapsulate(#[from] EncapsulateError),
    /// Session in wrong state for operation.
    #[error("session in wrong state: {current:?}, expected {expected}")]
    InvalidState {
        /// Current state.
        current: KemSessionState,
        /// Expected state(s).
        expected: &'static str,
    },
    /// Local share missing.
    #[error("local share not set")]
    MissingShare,
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Number of partial decryptions collected.
        have: usize,
        /// Threshold T.
        need: u32,
    },
    /// Algorithm mismatch.
    #[error("algorithm mismatch: share={share}, session={session}")]
    AlgorithmMismatch {
        /// Share algorithm.
        share: String,
        /// Session algorithm.
        session: String,
    },
}

impl KemSession {
    /// Create a new decapsulation session.
    pub fn new(params: KemSessionParams) -> Self {
        Self {
            params,
            state: KemSessionState::Pending,
            local_share: None,
            partial_decryptions: Vec::new(),
            result: None,
            created_at: Utc::now(),
        }
    }

    /// Provide the local share. Must be called before round 1.
    pub fn set_local_share(&mut self, share: ThresholdShare) -> Result<(), KemError> {
        if share.algorithm != self.params.algorithm {
            return Err(KemError::AlgorithmMismatch {
                share: share.algorithm,
                session: self.params.algorithm.clone(),
            });
        }
        self.local_share = Some(share);
        Ok(())
    }

    /// Submit a partial decryption from another party.
    pub fn submit_partial(&mut self, partial: PartialDecryption) -> Result<(), KemError> {
        if self.state != KemSessionState::Pending && self.state != KemSessionState::Round1Complete
        {
            return Err(KemError::InvalidState {
                current: self.state,
                expected: "pending or round1_complete",
            });
        }
        self.partial_decryptions.push(partial);
        Ok(())
    }

    /// Try to complete the decapsulation.
    pub fn try_complete(&mut self) -> Result<Vec<u8>, KemError> {
        let needed = self.params.threshold as usize;
        if self.partial_decryptions.len() < needed {
            return Err(KemError::ThresholdNotMet {
                have: self.partial_decryptions.len(),
                need: self.params.threshold,
            });
        }
        if self.local_share.is_none() {
            return Err(KemError::MissingShare);
        }

        // Mock implementation: XOR all partial decryptions together.
        // Real algorithm crates provide the actual decapsulation logic.
        let mut combined = vec![0u8; 32];
        for partial in &self.partial_decryptions {
            for (i, b) in partial.bytes.iter().take(32).enumerate() {
                combined[i] ^= b;
            }
        }

        self.result = Some(combined.clone());
        self.state = KemSessionState::Completed;
        Ok(combined)
    }

    /// Current session state.
    pub fn state(&self) -> KemSessionState {
        self.state
    }

    /// When the session was created.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Session parameters.
    pub fn params(&self) -> &KemSessionParams {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encapsulate::EncapsulatedKey;

    fn sample_params() -> KemSessionParams {
        KemSessionParams {
            algorithm: "mock-threshold-kem".into(),
            quorum_id: "test-quorum".into(),
            threshold: 2,
            num_parties: 3,
            this_party_idx: 0,
            encapsulated_key: EncapsulatedKey {
                algorithm: "mock-threshold-kem".into(),
                bytes: vec![0u8; 32],
            },
        }
    }

    #[test]
    fn session_lifecycle_mock() {
        let mut session = KemSession::new(sample_params());
        let share = ThresholdShare::new("mock-threshold-kem", 0, vec![1u8; 32]);
        session.set_local_share(share).unwrap();

        session
            .submit_partial(PartialDecryption {
                party_index: 1,
                bytes: vec![0xAA; 32],
            })
            .unwrap();
        session
            .submit_partial(PartialDecryption {
                party_index: 2,
                bytes: vec![0x55; 32],
            })
            .unwrap();

        let result = session.try_complete().unwrap();
        assert_eq!(result.len(), 32);
        // XOR of 0xAA and 0x55 = 0xFF
        assert_eq!(result[0], 0xFF);
        assert_eq!(session.state(), KemSessionState::Completed);
    }

    #[test]
    fn threshold_not_met_fails() {
        let mut session = KemSession::new(sample_params());
        let share = ThresholdShare::new("mock-threshold-kem", 0, vec![1u8; 32]);
        session.set_local_share(share).unwrap();
        session
            .submit_partial(PartialDecryption {
                party_index: 1,
                bytes: vec![0xAA; 32],
            })
            .unwrap();
        let result = session.try_complete();
        assert!(matches!(result, Err(KemError::ThresholdNotMet { .. })));
    }

    #[test]
    fn algorithm_mismatch_rejected() {
        let mut session = KemSession::new(sample_params());
        let bad_share = ThresholdShare::new("different-alg", 0, vec![]);
        let result = session.set_local_share(bad_share);
        assert!(matches!(result, Err(KemError::AlgorithmMismatch { .. })));
    }
}
