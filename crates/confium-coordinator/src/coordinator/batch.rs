//! Batch signing — coordinate multiple messages under one batch ID.
//!
//! High-volume signers produce many signatures per quorum activation.
//! The batch API creates N sessions under one batch ID, amortizing
//! quorum coordination overhead. Each message gets its own session
//! (so each gets its own audit trail), but they share the same
//! quorum, threshold, and lifecycle.

use crate::coordinator::coordinator::Coordinator;
use crate::coordinator::session::{
    AggregatedSignature, SessionError, SessionId, SessionRequest, SessionState,
};
use std::collections::HashMap;

/// A batch signing request: N messages, same quorum.
#[derive(Debug, Clone)]
pub struct BatchSessionRequest {
    /// Quorum authorizing all signatures in this batch.
    pub quorum_id: String,
    /// Threshold scheme.
    pub scheme: String,
    /// Messages to sign (one session per message).
    pub messages: Vec<Vec<u8>>,
    /// Threshold T.
    pub threshold: u32,
    /// Total party count N.
    pub num_parties: u32,
    /// Unlock window in minutes.
    pub unlock_window_minutes: u32,
    /// Requesting actor.
    pub requested_by: String,
}

/// A batch of related sessions tracked under one batch ID.
#[derive(Debug, Clone)]
pub struct BatchSession {
    /// Batch identifier.
    pub batch_id: String,
    /// Individual session IDs (one per message).
    pub session_ids: Vec<SessionId>,
    /// The original batch request.
    pub request: BatchSessionRequest,
}

/// Errors during batch operations.
#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    /// A session in the batch failed.
    #[error("session {session_id} failed: {error}")]
    SessionFailed {
        /// Which session failed.
        session_id: SessionId,
        /// The error.
        error: String,
    },
    /// Batch not found.
    #[error("batch not found: {0}")]
    NotFound(String),
    /// Empty batch.
    #[error("batch has no messages")]
    Empty,
    /// Session creation failed.
    #[error("session creation failed: {0}")]
    SessionCreation(#[from] SessionError),
}

/// Batch session manager. Wraps a Coordinator to provide batch
/// creation and aggregation.
pub struct BatchSigner<'a> {
    coordinator: &'a mut Coordinator,
    batches: HashMap<String, BatchSession>,
    next_batch_id: u64,
}

impl<'a> BatchSigner<'a> {
    /// Create a new batch signer wrapping a coordinator.
    pub fn new(coordinator: &'a mut Coordinator) -> Self {
        Self {
            coordinator,
            batches: HashMap::new(),
            next_batch_id: 0,
        }
    }

    /// Create a batch of sessions — one per message.
    /// Returns the batch ID and the list of session IDs.
    pub fn create_batch(&mut self, request: BatchSessionRequest) -> Result<String, BatchError> {
        if request.messages.is_empty() {
            return Err(BatchError::Empty);
        }

        let batch_id = format!("batch-{}", self.next_batch_id);
        self.next_batch_id += 1;

        let mut session_ids = Vec::with_capacity(request.messages.len());
        for message in &request.messages {
            let req = SessionRequest {
                quorum_id: request.quorum_id.clone(),
                scheme: request.scheme.clone(),
                message: message.clone(),
                threshold: request.threshold,
                num_parties: request.num_parties,
                unlock_window_minutes: request.unlock_window_minutes,
                requested_by: request.requested_by.clone(),
            };
            let sid = self.coordinator.create_session(req)?;
            session_ids.push(sid);
        }

        let count = session_ids.len();
        self.batches.insert(
            batch_id.clone(),
            BatchSession {
                batch_id: batch_id.clone(),
                session_ids,
                request,
            },
        );

        tracing::info!(batch_id = %batch_id, sessions = count, "batch created");
        Ok(batch_id)
    }

    /// Aggregate all sessions in a batch. All sessions must have
    /// received T shares. Returns one signature per message.
    pub fn aggregate_batch(
        &mut self,
        batch_id: &str,
    ) -> Result<Vec<AggregatedSignature>, BatchError> {
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| BatchError::NotFound(batch_id.into()))?;

        let session_ids: Vec<SessionId> = batch.session_ids.clone();
        let mut results = Vec::with_capacity(session_ids.len());

        for sid in session_ids {
            match self.coordinator.aggregate(&sid) {
                Ok(sig) => results.push(sig),
                Err(e) => {
                    return Err(BatchError::SessionFailed {
                        session_id: sid,
                        error: format!("{e:?}"),
                    });
                }
            }
        }

        tracing::info!(batch_id = %batch_id, signatures = results.len(), "batch aggregated");
        Ok(results)
    }

    /// Get the session IDs for a batch.
    pub fn batch_session_ids(&self, batch_id: &str) -> Option<&[SessionId]> {
        self.batches.get(batch_id).map(|b| b.session_ids.as_slice())
    }

    /// Number of batches managed.
    pub fn batch_count(&self) -> usize {
        self.batches.len()
    }

    /// Check if all sessions in a batch have reached the threshold
    /// share count (ready for aggregation).
    pub fn is_batch_ready(&self, batch_id: &str) -> bool {
        let batch = match self.batches.get(batch_id) {
            Some(b) => b,
            None => return false,
        };
        batch.session_ids.iter().all(|sid| {
            if let (Some(threshold), Some(count)) = (
                self.coordinator.session_threshold(sid),
                self.coordinator.session_share_count(sid),
            ) {
                count >= threshold as usize
            } else {
                false
            }
        })
    }

    /// Get batch states as a summary.
    pub fn batch_states(&self, batch_id: &str) -> Option<Vec<SessionState>> {
        self.batches.get(batch_id).map(|batch| {
            batch
                .session_ids
                .iter()
                .filter_map(|sid| self.coordinator.session_state(sid))
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::coordinator::Coordinator;

    fn make_batch_request(n: usize) -> BatchSessionRequest {
        BatchSessionRequest {
            quorum_id: "q1".into(),
            scheme: "CMP20".into(),
            messages: (0..n).map(|i| vec![i as u8; 32]).collect(),
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: 60,
            requested_by: "tester".into(),
        }
    }

    #[test]
    fn create_batch_produces_n_sessions() {
        let mut coord = Coordinator::new();
        let mut batcher = BatchSigner::new(&mut coord);
        let batch_id = batcher.create_batch(make_batch_request(5)).unwrap();
        assert!(batch_id.starts_with("batch-"));
        assert_eq!(batcher.batch_session_ids(&batch_id).unwrap().len(), 5);
        assert_eq!(batcher.batch_count(), 1);
        assert_eq!(coord.session_count(), 5);
    }

    #[test]
    fn empty_batch_rejected() {
        let mut coord = Coordinator::new();
        let mut batcher = BatchSigner::new(&mut coord);
        let req = BatchSessionRequest {
            messages: vec![],
            ..make_batch_request(0)
        };
        assert!(batcher.create_batch(req).is_err());
    }

    #[test]
    fn multiple_batches_have_incrementing_ids() {
        let mut coord = Coordinator::new();
        let mut batcher = BatchSigner::new(&mut coord);
        let id1 = batcher.create_batch(make_batch_request(1)).unwrap();
        let id2 = batcher.create_batch(make_batch_request(1)).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn aggregate_unknown_batch_errors() {
        let mut coord = Coordinator::new();
        let mut batcher = BatchSigner::new(&mut coord);
        assert!(batcher.aggregate_batch("nonexistent").is_err());
    }

    #[test]
    fn batch_ready_false_when_shares_missing() {
        let mut coord = Coordinator::new();
        let mut batcher = BatchSigner::new(&mut coord);
        let batch_id = batcher.create_batch(make_batch_request(2)).unwrap();
        assert!(!batcher.is_batch_ready(&batch_id));
    }

    #[test]
    fn batch_states_returns_per_session_states() {
        let mut coord = Coordinator::new();
        let mut batcher = BatchSigner::new(&mut coord);
        let batch_id = batcher.create_batch(make_batch_request(3)).unwrap();
        let states = batcher.batch_states(&batch_id).unwrap();
        assert_eq!(states.len(), 3);
        assert!(states.iter().all(|s| *s == SessionState::Pending));
    }

    #[test]
    fn single_message_batch_works() {
        let mut coord = Coordinator::new();
        let mut batcher = BatchSigner::new(&mut coord);
        let batch_id = batcher.create_batch(make_batch_request(1)).unwrap();
        assert_eq!(batcher.batch_session_ids(&batch_id).unwrap().len(), 1);
    }
}
