//! The revocation service.

use std::collections::HashMap;

use crate::revocation::revocation_blob::{RevocationBlob, RevocationError};
use crate::revocation::revocation_submission::{Submission, SubmissionState};

/// The revocation service.
pub struct RevocationService {
    service_quorum_id: String,
    submissions: HashMap<String, Submission>,
}

impl RevocationService {
    /// Construct a new service backed by the named quorum.
    pub fn new(quorum_id: impl Into<String>) -> Self {
        Self {
            service_quorum_id: quorum_id.into(),
            submissions: HashMap::new(),
        }
    }

    /// Quorum identifier backing this service.
    pub fn quorum_id(&self) -> &str {
        &self.service_quorum_id
    }

    /// User-side: prepare a revocation blob.
    ///
    /// In a real implementation this encrypts (revocation_signature + public_key)
    /// to the service quorum's threshold public key.
    pub fn prepare_revocation_blob(
        &self,
        user_email: &str,
        key_fingerprint: &str,
        revocation_signature: &[u8],
        public_key: &[u8],
        encapsulator: &dyn Encapsulator,
    ) -> Result<RevocationBlob, RevocationError> {
        let (encapsulated_key, shared_secret) = encapsulator
            .encapsulate(&self.service_quorum_id)
            .map_err(|e| RevocationError::Malformed(e))?;

        // Encrypt payload with mock AEAD (XOR shared_secret).
        let mut payload = Vec::new();
        payload.extend_from_slice(revocation_signature);
        payload.extend_from_slice(public_key);
        let ciphertext: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ shared_secret[i % shared_secret.len()])
            .collect();

        Ok(RevocationBlob {
            user_email: user_email.into(),
            key_fingerprint: key_fingerprint.into(),
            encapsulated_key,
            ciphertext,
            nonce: vec![0u8; 12],
        })
    }

    /// Service-side: submit a blob for processing.
    pub fn submit(
        &mut self,
        blob: RevocationBlob,
        verification_token: &str,
    ) -> Result<String, RevocationError> {
        if verification_token.is_empty() {
            return Err(RevocationError::InvalidToken(
                "token must be non-empty".into(),
            ));
        }
        let id = format!("sub-{}", self.submissions.len() + 1);
        let submission = Submission::new(id.clone(), blob);
        self.submissions.insert(id.clone(), submission);
        Ok(id)
    }

    /// Service-side: process first confirmation for a submission.
    pub fn confirm_first(&mut self, submission_id: &str) -> Result<(), RevocationError> {
        let sub = self.submissions.get_mut(submission_id).ok_or_else(|| {
            RevocationError::Malformed(format!("unknown submission {submission_id}"))
        })?;
        sub.confirm_first()
            .map_err(|e| RevocationError::EmailVerificationFailed(e))
    }

    /// Service-side: process second confirmation (after 24h delay).
    pub fn confirm_second(&mut self, submission_id: &str) -> Result<(), RevocationError> {
        let sub = self.submissions.get_mut(submission_id).ok_or_else(|| {
            RevocationError::Malformed(format!("unknown submission {submission_id}"))
        })?;
        sub.confirm_second()
            .map_err(|e| RevocationError::EmailVerificationFailed(e))
    }

    /// Service-side: process pending submissions that have reached second confirmation.
    /// Returns the number of submissions processed.
    pub fn process_pending(&mut self) -> Result<usize, RevocationError> {
        let mut count = 0;
        for sub in self.submissions.values_mut() {
            if sub.state == SubmissionState::SecondConfirmed {
                sub.mark_decrypted()
                    .map_err(|e| RevocationError::ThresholdDecryption(e))?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Service-side: publish a processed submission to keyservers.
    pub fn publish(&mut self, submission_id: &str) -> Result<(), RevocationError> {
        let sub = self.submissions.get_mut(submission_id).ok_or_else(|| {
            RevocationError::Malformed(format!("unknown submission {submission_id}"))
        })?;
        sub.mark_published()
            .map_err(|e| RevocationError::Publish(e))
    }

    /// Number of pending submissions.
    pub fn pending_count(&self) -> usize {
        self.submissions
            .values()
            .filter(|s| {
                !matches!(
                    s.state,
                    SubmissionState::Published | SubmissionState::Cancelled
                )
            })
            .count()
    }

    /// Lookup a submission by ID.
    pub fn submission(&self, id: &str) -> Option<&Submission> {
        self.submissions.get(id)
    }
}

/// Encapsulator hook — caller provides concrete threshold KEM impl.
pub trait Encapsulator {
    /// Encapsulate to a quorum by ID. Returns (encapsulated_key, shared_secret).
    fn encapsulate(&self, quorum_id: &str) -> Result<(Vec<u8>, Vec<u8>), String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEncapsulator;
    impl Encapsulator for MockEncapsulator {
        fn encapsulate(&self, _quorum_id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
            Ok((vec![0u8; 32], vec![0u8; 32]))
        }
    }

    #[test]
    fn service_lifecycle_mock() {
        let mut service = RevocationService::new("tb-revocation-quorum");

        let blob = service
            .prepare_revocation_blob(
                "alice@example.com",
                "ABCD1234",
                &[1u8, 2, 3, 4],
                &[5u8, 6, 7, 8],
                &MockEncapsulator,
            )
            .unwrap();

        let id = service.submit(blob, "valid-token").unwrap();
        service.confirm_first(&id).unwrap();

        // Mock delay elapsed by directly setting state
        {
            let sub_mut = service.submissions.get_mut(&id).unwrap();
            sub_mut.delay_until = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        }

        service.confirm_second(&id).unwrap();
        let processed = service.process_pending().unwrap();
        assert_eq!(processed, 1);
        service.publish(&id).unwrap();

        assert_eq!(
            service.submission(&id).unwrap().state,
            SubmissionState::Published
        );
    }

    #[test]
    fn submit_with_empty_token_fails() {
        let mut service = RevocationService::new("q");
        let blob = service
            .prepare_revocation_blob("a@b", "X", &[], &[], &MockEncapsulator)
            .unwrap();
        let result = service.submit(blob, "");
        assert!(matches!(result, Err(RevocationError::InvalidToken(_))));
    }
}
