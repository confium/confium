//! FROST coordinator integration — wire FROST into the coordinator.

use crate::coordinator::coordinator::Coordinator;
use crate::coordinator::session::{SessionId, SessionRequest, SessionState};
use serde::{Deserialize, Serialize};

/// FROST signing scheme type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrostScheme {
    Ed25519,
    P256,
}

/// FROST session metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostSession {
    pub session_id: SessionId,
    pub scheme: FrostScheme,
    pub threshold: u32,
    pub party_count: u32,
    pub message_hash_hex: String,
    pub partial_signatures: Vec<PartialFrostSig>,
}

/// A partial FROST signature from one party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialFrostSig {
    pub signer_id: String,
    pub party_idx: u32,
    pub partial_sig_hex: String,
}

impl FrostSession {
    pub fn new(
        session_id: &str,
        scheme: FrostScheme,
        threshold: u32,
        party_count: u32,
        message: &[u8],
    ) -> Self {
        Self {
            session_id: session_id.into(),
            scheme,
            threshold,
            party_count,
            message_hash_hex: hex::encode(message),
            partial_signatures: Vec::new(),
        }
    }

    pub fn submit_partial(&mut self, partial: PartialFrostSig) -> Result<(), String> {
        if partial.party_idx == 0 || partial.party_idx > self.party_count {
            return Err("invalid party index".into());
        }
        if self
            .partial_signatures
            .iter()
            .any(|s| s.party_idx == partial.party_idx)
        {
            return Err("duplicate partial signature".into());
        }
        self.partial_signatures.push(partial);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.partial_signatures.len() >= self.threshold as usize
    }

    pub fn missing_parties(&self) -> Vec<u32> {
        (1..=self.party_count)
            .filter(|i| !self.partial_signatures.iter().any(|s| s.party_idx == *i))
            .collect()
    }

    pub fn ordered_partials(&self) -> Vec<&PartialFrostSig> {
        let mut partials = self.partial_signatures.iter().collect::<Vec<_>>();
        partials.sort_by_key(|p| p.party_idx);
        partials
    }
}

/// Create a FROST signing session on the coordinator.
pub fn create_frost_session(
    coordinator: &mut Coordinator,
    scheme: FrostScheme,
    quorum_id: &str,
    threshold: u32,
    party_count: u32,
    message: &[u8],
) -> Result<(SessionId, FrostSession), String> {
    let scheme_name = match scheme {
        FrostScheme::Ed25519 => "FROST-ed25519",
        FrostScheme::P256 => "FROST-P256",
    };
    let request = SessionRequest {
        quorum_id: quorum_id.into(),
        scheme: scheme_name.into(),
        message: message.to_vec(),
        threshold,
        num_parties: party_count,
        unlock_window_minutes: 60,
        requested_by: "frost-integration".into(),
    };
    let session_id = coordinator
        .create_session(request)
        .map_err(|e| format!("{e:?}"))?;
    let frost_session = FrostSession::new(&session_id, scheme, threshold, party_count, message);
    Ok((session_id, frost_session))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frost_session_new() {
        let session = FrostSession::new("s1", FrostScheme::P256, 2, 3, b"message");
        assert_eq!(session.threshold, 2);
        assert_eq!(session.party_count, 3);
        assert!(!session.is_ready());
    }

    #[test]
    fn submit_partial_increments() {
        let mut session = FrostSession::new("s1", FrostScheme::Ed25519, 2, 3, b"msg");
        session
            .submit_partial(PartialFrostSig {
                signer_id: "a".into(),
                party_idx: 1,
                partial_sig_hex: "abc".into(),
            })
            .unwrap();
        assert_eq!(session.partial_signatures.len(), 1);
    }

    #[test]
    fn ready_at_threshold() {
        let mut session = FrostSession::new("s1", FrostScheme::P256, 2, 3, b"msg");
        session
            .submit_partial(PartialFrostSig {
                signer_id: "a".into(),
                party_idx: 1,
                partial_sig_hex: "aa".into(),
            })
            .unwrap();
        session
            .submit_partial(PartialFrostSig {
                signer_id: "b".into(),
                party_idx: 2,
                partial_sig_hex: "bb".into(),
            })
            .unwrap();
        assert!(session.is_ready());
    }

    #[test]
    fn duplicate_partial_rejected() {
        let mut session = FrostSession::new("s1", FrostScheme::P256, 2, 3, b"msg");
        session
            .submit_partial(PartialFrostSig {
                signer_id: "a".into(),
                party_idx: 1,
                partial_sig_hex: "aa".into(),
            })
            .unwrap();
        assert!(
            session
                .submit_partial(PartialFrostSig {
                    signer_id: "a".into(),
                    party_idx: 1,
                    partial_sig_hex: "aa".into(),
                })
                .is_err()
        );
    }

    #[test]
    fn invalid_party_idx_rejected() {
        let mut session = FrostSession::new("s1", FrostScheme::P256, 2, 3, b"msg");
        assert!(
            session
                .submit_partial(PartialFrostSig {
                    signer_id: "x".into(),
                    party_idx: 0,
                    partial_sig_hex: "x".into(),
                })
                .is_err()
        );
        assert!(
            session
                .submit_partial(PartialFrostSig {
                    signer_id: "x".into(),
                    party_idx: 99,
                    partial_sig_hex: "x".into(),
                })
                .is_err()
        );
    }

    #[test]
    fn missing_parties_listed() {
        let mut session = FrostSession::new("s1", FrostScheme::P256, 3, 5, b"msg");
        session
            .submit_partial(PartialFrostSig {
                signer_id: "a".into(),
                party_idx: 1,
                partial_sig_hex: "a".into(),
            })
            .unwrap();
        session
            .submit_partial(PartialFrostSig {
                signer_id: "c".into(),
                party_idx: 3,
                partial_sig_hex: "c".into(),
            })
            .unwrap();
        assert_eq!(session.missing_parties(), vec![2, 4, 5]);
    }

    #[test]
    fn ordered_partials_sorted() {
        let mut session = FrostSession::new("s1", FrostScheme::P256, 3, 5, b"msg");
        session
            .submit_partial(PartialFrostSig {
                signer_id: "c".into(),
                party_idx: 3,
                partial_sig_hex: "c".into(),
            })
            .unwrap();
        session
            .submit_partial(PartialFrostSig {
                signer_id: "a".into(),
                party_idx: 1,
                partial_sig_hex: "a".into(),
            })
            .unwrap();
        let ordered = session.ordered_partials();
        assert_eq!(ordered[0].party_idx, 1);
        assert_eq!(ordered[1].party_idx, 3);
    }

    #[test]
    fn create_frost_session_on_coordinator() {
        let mut coord = Coordinator::new();
        let (sid, frost) =
            create_frost_session(&mut coord, FrostScheme::P256, "quorum-1", 2, 3, b"hello")
                .unwrap();
        assert!(!sid.is_empty());
        assert_eq!(frost.scheme, FrostScheme::P256);
        assert_eq!(coord.session_count(), 1);
    }

    #[test]
    fn frost_session_serializes() {
        let session = FrostSession::new("s1", FrostScheme::Ed25519, 2, 3, b"msg");
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("Ed25519"));
    }
}
