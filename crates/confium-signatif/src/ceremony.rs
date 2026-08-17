//! Ceremony records (SIGNATIF §17).
//!
//! Every threshold ceremony — DKG, re-share, signing, revocation —
//! produces a verifiable [`CeremonyTranscript`]: the participants with
//! their contribution proofs, the quorum parameters, the canonical
//! payload hash signed, the aggregate threshold signature produced,
//! and a timestamp. Each participant signs the transcript attesting
//! their participation. The [`ceremony_audit`] algorithm verifies
//! every member signature, the aggregate signature, the T-of-N
//! participation, the transparency-log cross-reference, and timestamp
//! consistency.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{SignatifError, SignatifResult};
use crate::graph::{Quorum, SignatureVerifier};

/// One participant's contribution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Participant identity (organization or member key fingerprint).
    pub id: String,
    /// The participant's public key.
    pub public_key: Vec<u8>,
    /// Proof of contribution — for DKG, the member's PoP over the
    /// session transcript (rogue-key prevention, §10); for signing,
    /// the member's partial-signature commitment.
    pub contribution_proof: Vec<u8>,
    /// The participant's signature over the transcript participation
    /// binding bytes (`transcript-signing` requirement).
    pub participation_signature: Vec<u8>,
}

/// A verifiable record of one threshold ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyTranscript {
    /// Ceremony type (from the ceremony-type registry): dkg, reshare,
    /// sign, revoke, rotation.
    pub ceremony_type: String,
    /// Participating members with contribution proofs.
    pub participants: Vec<Participant>,
    /// Quorum parameters of the authority that ran the ceremony.
    pub quorum: Quorum,
    /// The canonical payload hash the ceremony signed.
    pub payload_hash: [u8; 32],
    /// The aggregate threshold signature produced.
    pub aggregate_signature: Vec<u8>,
    /// The authority's aggregate public key (verifies the aggregate).
    pub aggregate_key: Vec<u8>,
    /// When the ceremony concluded.
    pub timestamp: DateTime<Utc>,
    /// Transparency-log sequence of the artifact/certificate the
    /// ceremony produced (`transcript-log-cross-reference`).
    pub log_sequence: u64,
}

impl CeremonyTranscript {
    /// The bytes each participant signs to attest participation:
    /// ceremony type, member identity, quorum, payload hash, timestamp.
    pub fn participation_bytes(&self, member_id: &str) -> SignatifResult<Vec<u8>> {
        let v = serde_json::json!({
            "ceremony_type": self.ceremony_type,
            "member": member_id,
            "quorum": self.quorum,
            "payload_hash": hex::encode(self.payload_hash),
            "timestamp": self.timestamp.to_rfc3339(),
        });
        Ok(crate::jcs::canonicalize(&v)?.into_bytes())
    }
}

/// The audit algorithm (`audit-algorithm` requirement): verify each
/// member participation signature, verify the aggregate threshold
/// signature against the published aggregate key, confirm at least T
/// of N members participated, cross-reference the payload with the
/// transparency log entry, and confirm timestamp consistency.
///
/// `log_entry_payload_hash` is the hash recovered from the referenced
/// transparency-log sequence number.
///
/// # Errors
///
/// Returns [`SignatifError::Ceremony`] with a precise reason for every
/// failed audit step.
pub fn ceremony_audit(
    transcript: &CeremonyTranscript,
    verifier: &dyn SignatureVerifier,
    log_entry_payload_hash: Option<&[u8; 32]>,
) -> SignatifResult<()> {
    // 1. Member participation signatures.
    for p in &transcript.participants {
        let bytes = transcript.participation_bytes(&p.id)?;
        if !verifier.verify(&p.public_key, &bytes, &p.participation_signature) {
            return Err(SignatifError::Ceremony(format!(
                "participation signature of member {} failed",
                p.id
            )));
        }
    }

    // 2. Quorum: at least T of N participated, N consistent.
    if transcript.participants.len() < transcript.quorum.t as usize {
        return Err(SignatifError::Ceremony(format!(
            "quorum not met: {} of {} required, {} participated",
            transcript.quorum.t,
            transcript.quorum.n,
            transcript.participants.len()
        )));
    }
    if transcript.participants.len() > transcript.quorum.n as usize {
        return Err(SignatifError::Ceremony(format!(
            "more participants ({}) than committee size N ({})",
            transcript.participants.len(),
            transcript.quorum.n
        )));
    }

    // 3. Aggregate threshold signature over the payload hash.
    if !verifier.verify(
        &transcript.aggregate_key,
        &transcript.payload_hash,
        &transcript.aggregate_signature,
    ) {
        return Err(SignatifError::Ceremony(
            "aggregate threshold signature failed".into(),
        ));
    }

    // 4. Transparency-log cross-reference.
    match log_entry_payload_hash {
        Some(h) if *h != transcript.payload_hash => {
            return Err(SignatifError::Ceremony(
                "transparency log entry payload hash mismatch".into(),
            ));
        }
        None => {
            return Err(SignatifError::Ceremony(
                "transparency log entry not available".into(),
            ));
        }
        _ => {}
    }

    // 5. Timestamp consistency: not in the future.
    if transcript.timestamp > Utc::now() {
        return Err(SignatifError::Ceremony(
            "transcript timestamp is in the future".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn generate_key() -> ed25519_dalek::SigningKey {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    struct Ed25519Verifier;

    impl SignatureVerifier for Ed25519Verifier {
        fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            use ed25519_dalek::Signature;
            use ed25519_dalek::Verifier;
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk.try_into().unwrap()) else {
                return false;
            };
            let Ok(signature) = Signature::from_slice(sig) else {
                return false;
            };
            vk.verify(msg, &signature).is_ok()
        }
    }

    fn transcript(t: u32, n: u32, participating: usize) -> (CeremonyTranscript, [u8; 32]) {
        let payload_hash = [7u8; 32];
        let timestamp = Utc::now();
        let mut participants = Vec::new();
        for i in 0..participating {
            let sk = generate_key();
            let template = CeremonyTranscript {
                ceremony_type: "dkg".into(),
                participants: vec![],
                quorum: Quorum { t, n },
                payload_hash,
                aggregate_signature: vec![],
                aggregate_key: vec![],
                timestamp,
                log_sequence: 99,
            };
            let bytes = template.participation_bytes(&format!("m{i}")).unwrap();
            participants.push(Participant {
                id: format!("m{i}"),
                public_key: sk.verifying_key().as_bytes().to_vec(),
                contribution_proof: sk.sign(&bytes).to_bytes().to_vec(),
                participation_signature: sk.sign(&bytes).to_bytes().to_vec(),
            });
        }
        let agg_sk = generate_key();
        let transcript = CeremonyTranscript {
            ceremony_type: "dkg".into(),
            participants,
            quorum: Quorum { t, n },
            payload_hash,
            aggregate_signature: agg_sk.sign(&payload_hash).to_bytes().to_vec(),
            aggregate_key: agg_sk.verifying_key().as_bytes().to_vec(),
            timestamp,
            log_sequence: 99,
        };
        (transcript, payload_hash)
    }

    #[test]
    fn audit_passes_for_valid_transcript() {
        let (t, hash) = transcript(2, 3, 3);
        // Re-sign participation signatures correctly (helper signed
        // participation with same key already).
        assert!(ceremony_audit(&t, &Ed25519Verifier, Some(&hash)).is_ok());
    }

    #[test]
    fn audit_fails_below_quorum() {
        let (t, hash) = transcript(2, 3, 1);
        assert!(ceremony_audit(&t, &Ed25519Verifier, Some(&hash)).is_err());
    }

    #[test]
    fn audit_fails_on_log_mismatch() {
        let (t, _) = transcript(2, 3, 3);
        let wrong = [0u8; 32];
        let err = ceremony_audit(&t, &Ed25519Verifier, Some(&wrong)).unwrap_err();
        assert!(err.to_string().contains("log entry"));
    }

    #[test]
    fn audit_fails_on_bad_aggregate() {
        let (mut t, hash) = transcript(2, 3, 3);
        t.aggregate_signature[0] ^= 1;
        assert!(ceremony_audit(&t, &Ed25519Verifier, Some(&hash)).is_err());
    }
}
