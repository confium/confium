//! Submission lifecycle.

use crate::revocation::revocation_blob::RevocationBlob;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// A revocation submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Submission {
    /// Unique submission ID.
    pub id: String,
    /// The blob being processed.
    pub blob: RevocationBlob,
    /// When the submission was first received.
    pub submitted_at: DateTime<Utc>,
    /// Current state.
    pub state: SubmissionState,
    /// When the first confirmation was sent (if any).
    pub first_confirmation_at: Option<DateTime<Utc>>,
    /// 24-hour delay end time (if first confirmation received).
    pub delay_until: Option<DateTime<Utc>>,
}

/// Submission state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionState {
    /// Submission received; awaiting email verification.
    AwaitingEmailVerification,
    /// Email verified; first confirmation sent; awaiting 24h delay.
    FirstConfirmedDelay,
    /// Second confirmation received; ready to process.
    SecondConfirmed,
    /// Threshold decryption ceremony completed.
    Decrypted,
    /// Revocation signature published to keyservers.
    Published,
    /// Cancelled by user.
    Cancelled,
    /// Expired (delay elapsed without confirmation).
    Expired,
}

impl Submission {
    /// Construct a new submission.
    pub fn new(id: impl Into<String>, blob: RevocationBlob) -> Self {
        Self {
            id: id.into(),
            blob,
            submitted_at: Utc::now(),
            state: SubmissionState::AwaitingEmailVerification,
            first_confirmation_at: None,
            delay_until: None,
        }
    }

    /// Move to FirstConfirmedDelay (after email verification).
    pub fn confirm_first(&mut self) -> Result<(), String> {
        if self.state != SubmissionState::AwaitingEmailVerification {
            return Err(format!("invalid state: {:?}", self.state));
        }
        let now = Utc::now();
        self.first_confirmation_at = Some(now);
        self.delay_until = Some(now + Duration::hours(24));
        self.state = SubmissionState::FirstConfirmedDelay;
        Ok(())
    }

    /// Move to SecondConfirmed (after 24h delay).
    pub fn confirm_second(&mut self) -> Result<(), String> {
        if self.state != SubmissionState::FirstConfirmedDelay {
            return Err(format!("invalid state: {:?}", self.state));
        }
        if let Some(until) = self.delay_until {
            if Utc::now() < until {
                return Err("24h delay not yet elapsed".into());
            }
        }
        self.state = SubmissionState::SecondConfirmed;
        Ok(())
    }

    /// Mark threshold decryption completed.
    pub fn mark_decrypted(&mut self) -> Result<(), String> {
        if self.state != SubmissionState::SecondConfirmed {
            return Err(format!("invalid state: {:?}", self.state));
        }
        self.state = SubmissionState::Decrypted;
        Ok(())
    }

    /// Mark published to keyservers.
    pub fn mark_published(&mut self) -> Result<(), String> {
        if self.state != SubmissionState::Decrypted {
            return Err(format!("invalid state: {:?}", self.state));
        }
        self.state = SubmissionState::Published;
        Ok(())
    }

    /// Cancel.
    pub fn cancel(&mut self) -> Result<(), String> {
        if matches!(
            self.state,
            SubmissionState::Published | SubmissionState::Cancelled
        ) {
            return Err("cannot cancel terminal submission".into());
        }
        self.state = SubmissionState::Cancelled;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::revocation_blob::RevocationBlob;

    fn sample_blob() -> RevocationBlob {
        RevocationBlob {
            user_email: "alice@example.com".into(),
            key_fingerprint: "ABCDEF0123456789".into(),
            encapsulated_key: vec![0u8; 32],
            ciphertext: vec![0u8; 100],
            nonce: vec![0u8; 12],
        }
    }

    #[test]
    fn full_submission_lifecycle() {
        let mut sub = Submission::new("sub-1", sample_blob());
        assert_eq!(sub.state, SubmissionState::AwaitingEmailVerification);

        sub.confirm_first().unwrap();
        assert_eq!(sub.state, SubmissionState::FirstConfirmedDelay);

        // Mock delay elapsed
        sub.delay_until = Some(Utc::now() - Duration::hours(1));
        sub.confirm_second().unwrap();
        assert_eq!(sub.state, SubmissionState::SecondConfirmed);

        sub.mark_decrypted().unwrap();
        assert_eq!(sub.state, SubmissionState::Decrypted);

        sub.mark_published().unwrap();
        assert_eq!(sub.state, SubmissionState::Published);
    }

    #[test]
    fn confirm_second_before_delay_fails() {
        let mut sub = Submission::new("sub-2", sample_blob());
        sub.confirm_first().unwrap();
        // Set delay to future
        sub.delay_until = Some(Utc::now() + Duration::hours(24));
        let result = sub.confirm_second();
        assert!(result.is_err());
    }

    #[test]
    fn cancel_works_from_any_nonterminal_state() {
        let mut sub = Submission::new("sub-3", sample_blob());
        sub.cancel().unwrap();
        assert_eq!(sub.state, SubmissionState::Cancelled);
    }
}
