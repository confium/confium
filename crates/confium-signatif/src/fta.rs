//! Federated trust authorities and nested threshold (SIGNATIF §10).
//!
//! A federated trust authority (FTA) is a threshold group of
//! **independent organizations** sharing a single aggregate key: M-of-K
//! organizations must cooperate, and each organization may itself be a
//! threshold authority (nested threshold). No single organization
//! controls the authority, and an FTA may span hierarchies — its
//! artifacts are verifiable against the FTA's aggregate key and
//! recognized by all member hierarchies.
//!
//! Ceremony robustness (`ceremony-robustness`, `rogue-key-prevention`):
//!
//! - every member demonstrates **proof of possession** of the private
//!   key behind its contributed share during key generation, so a
//!   malicious member cannot register a crafted key that makes the
//!   aggregate equal to its solo key;
//! - **nonce commitment** (commit-then-reveal) prevents nonce bias;
//! - **identifiable abort** attributes a failed ceremony to the member
//!   causing the failure.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{SignatifError, SignatifResult};
use crate::graph::{Quorum, SignatureVerifier};

/// One member organization of a federated trust authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberOrg {
    /// Organization identity.
    pub id: String,
    /// The organization's contribution public key (its share or its
    /// inner authority's aggregate key when nested).
    pub public_key: Vec<u8>,
    /// The inner quorum when this member is itself a threshold
    /// authority (nested threshold).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner_quorum: Option<Quorum>,
}

/// A federated trust authority: M-of-K organizations, one aggregate key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedTrustAuthority {
    /// FTA identifier.
    pub id: String,
    /// Member organizations.
    pub members: Vec<MemberOrg>,
    /// Organizational quorum: M of K organizations must cooperate.
    pub org_quorum: Quorum,
    /// The FTA's aggregate public key.
    pub aggregate_key: Vec<u8>,
    /// Whether members may come from independent root hierarchies
    /// (hierarchy-spanning FTA — a trust bridge).
    pub hierarchy_spanning: bool,
}

impl FederatedTrustAuthority {
    /// Validate structural invariants: M <= K <= members, unique
    /// member ids, and — for nested members — inner quorum sanity.
    ///
    /// # Errors
    ///
    /// Encoding errors with a precise message for each violation.
    pub fn validate(&self) -> SignatifResult<()> {
        if self.org_quorum.t == 0 || self.org_quorum.t as usize > self.members.len() {
            return Err(SignatifError::Encoding(format!(
                "FTA {}: org quorum {} of {} inconsistent with {} members",
                self.id,
                self.org_quorum.t,
                self.org_quorum.n,
                self.members.len()
            )));
        }
        if self.org_quorum.n as usize != self.members.len() {
            return Err(SignatifError::Encoding(format!(
                "FTA {}: K ({}) must equal member count ({})",
                self.id,
                self.org_quorum.n,
                self.members.len()
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for m in &self.members {
            if !seen.insert(m.id.clone()) {
                return Err(SignatifError::Encoding(format!(
                    "FTA {}: duplicate member {}",
                    self.id, m.id
                )));
            }
            if let Some(q) = m.inner_quorum {
                Quorum::new(q.t, q.n)?;
            }
        }
        Ok(())
    }

    /// Whether signing by this FTA requires the given inner authority
    /// to first reach its own quorum (nested threshold composition).
    pub fn requires_inner_quorum(&self, org: &str) -> Option<Quorum> {
        self.members
            .iter()
            .find(|m| m.id == org)
            .and_then(|m| m.inner_quorum)
    }
}

/// Proof of possession contributed during DKG: the member's signature
/// over the session binding (authority id + nonce + its public key).
/// Verifying every contribution against its claimed key is the
/// rogue-key defense.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfPossession {
    /// Contributing member.
    pub member: String,
    /// The member's public key.
    pub public_key: Vec<u8>,
    /// Signature over the session binding bytes.
    pub signature: Vec<u8>,
}

/// A DKG session for forming (or re-sharing) an FTA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgSession {
    /// The authority being formed.
    pub authority_id: String,
    /// Session nonce — unique per ceremony.
    pub session_nonce: [u8; 32],
    /// The ceremony type (dkg, reshare).
    pub ceremony_type: String,
}

impl DkgSession {
    /// The bytes each member's proof of possession signs.
    pub fn pop_bytes(&self, member: &str, public_key: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.authority_id.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&self.session_nonce);
        bytes.push(0);
        bytes.extend_from_slice(member.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(public_key);
        bytes
    }

    /// Verify one contribution's proof of possession.
    fn verify_pop(&self, pop: &ProofOfPossession, verifier: &dyn SignatureVerifier) -> bool {
        verifier.verify(
            &pop.public_key,
            &self.pop_bytes(&pop.member, &pop.public_key),
            &pop.signature,
        )
    }

    /// Verify every contribution: each proof of possession checks out
    /// against its claimed key, and at least T of N members contributed.
    /// This is the rogue-key-attack prevention requirement.
    ///
    /// # Errors
    ///
    /// Ceremony errors naming the first offending member.
    pub fn verify_contributions(
        &self,
        pops: &[ProofOfPossession],
        quorum: Quorum,
        verifier: &dyn SignatureVerifier,
    ) -> SignatifResult<()> {
        let mut distinct = std::collections::BTreeSet::new();
        for pop in pops {
            if !self.verify_pop(pop, verifier) {
                return Err(SignatifError::Ceremony(format!(
                    "rogue-key defense: member {} failed proof of possession",
                    pop.member
                )));
            }
            distinct.insert(pop.member.clone());
        }
        if distinct.len() < quorum.t as usize {
            return Err(SignatifError::Ceremony(format!(
                "quorum not met: {} of {} required, {} contributed",
                quorum.t,
                quorum.n,
                distinct.len()
            )));
        }
        Ok(())
    }
}

/// A commit-then-reveal nonce commitment preventing nonce bias.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceCommitment {
    /// Committing member.
    pub member: String,
    /// SHA-256 commitment over the secret nonce.
    pub commitment: [u8; 32],
}

/// The reveal phase of a nonce commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceReveal {
    /// Revealing member.
    pub member: String,
    /// The secret nonce.
    pub nonce: [u8; 32],
}

impl NonceCommitment {
    /// Commit to a nonce.
    pub fn commit(member: impl Into<String>, nonce: &[u8; 32]) -> Self {
        Self {
            member: member.into(),
            commitment: Sha256::digest(nonce).into(),
        }
    }

    /// Verify a reveal against this commitment.
    pub fn verify(&self, reveal: &NonceReveal) -> bool {
        self.member == reveal.member
            && self.commitment == <[u8; 32]>::from(Sha256::digest(reveal.nonce))
    }
}

/// Identifiable abort: which member caused a ceremony failure and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortAttribution {
    /// The member at fault.
    pub faulty_member: String,
    /// Machine-readable reason.
    pub reason: AbortReason,
}

/// Why a ceremony aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    /// The member's proof of possession failed.
    BadProofOfPossession,
    /// The member's nonce reveal did not match its commitment.
    NonceCommitmentMismatch,
    /// The member failed to respond in its round.
    Timeout,
    /// The member's round contribution was malformed.
    MalformedContribution,
}

/// Attribute a failed DKG: find the first member whose contribution
/// fails (identifiable abort), or attribute a timeout to the members
/// that never contributed.
///
/// # Errors
///
/// Returns a ceremony error carrying the attribution.
pub fn attribute_dkg_failure(
    session: &DkgSession,
    expected: &[MemberOrg],
    pops: &[ProofOfPossession],
    commitments: &[NonceCommitment],
    reveals: &[NonceReveal],
    verifier: &dyn SignatureVerifier,
) -> Result<(), AbortAttribution> {
    let by_member: BTreeMap<&str, &ProofOfPossession> =
        pops.iter().map(|p| (p.member.as_str(), p)).collect();

    for org in expected {
        let Some(pop) = by_member.get(org.id.as_str()) else {
            return Err(AbortAttribution {
                faulty_member: org.id.clone(),
                reason: AbortReason::Timeout,
            });
        };
        if !session.verify_pop(pop, verifier) {
            return Err(AbortAttribution {
                faulty_member: org.id.clone(),
                reason: AbortReason::BadProofOfPossession,
            });
        }
    }

    let commits: BTreeMap<&str, &NonceCommitment> =
        commitments.iter().map(|c| (c.member.as_str(), c)).collect();
    let revealed: BTreeMap<&str, &NonceReveal> =
        reveals.iter().map(|r| (r.member.as_str(), r)).collect();
    for (member, commit) in &commits {
        match revealed.get(*member) {
            None => {
                return Err(AbortAttribution {
                    faulty_member: (*member).to_string(),
                    reason: AbortReason::Timeout,
                });
            }
            Some(reveal) => {
                if !commit.verify(reveal) {
                    return Err(AbortAttribution {
                        faulty_member: (*member).to_string(),
                        reason: AbortReason::NonceCommitmentMismatch,
                    });
                }
            }
        }
    }
    Ok(())
}

/// A membership change (join or leave) that must preserve the
/// aggregate key so historical artifacts remain valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipChange {
    /// The change kind.
    pub kind: MembershipChangeKind,
    /// The aggregate key before the change.
    pub aggregate_key_before: Vec<u8>,
    /// The aggregate key after the change.
    pub aggregate_key_after: Vec<u8>,
}

/// Join or leave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MembershipChangeKind {
    /// A member organization joins; its share commitment is included.
    Join {
        /// Joining organization.
        org: MemberOrg,
    },
    /// A member organization leaves.
    Leave {
        /// Leaving organization id.
        org_id: String,
    },
    /// The FTA dissolves: the aggregate key retires, but artifacts
    /// signed before dissolution stay valid.
    Dissolve,
}

impl MembershipChange {
    /// Validate the aggregate-key continuity invariant: join/leave
    /// MUST preserve the aggregate key (re-share); dissolution retires
    /// it.
    ///
    /// # Errors
    ///
    /// Encoding errors when continuity is violated.
    pub fn validate(&self) -> SignatifResult<()> {
        match &self.kind {
            MembershipChangeKind::Dissolve => Ok(()),
            _ => {
                if self.aggregate_key_before != self.aggregate_key_after {
                    return Err(SignatifError::Encoding(
                        "membership change altered the aggregate key — join/leave must re-share while preserving it"
                            .into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand_core::RngCore;

    fn generate_key() -> ed25519_dalek::SigningKey {
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

    fn org(id: &str, sk: &ed25519_dalek::SigningKey, inner: Option<Quorum>) -> MemberOrg {
        MemberOrg {
            id: id.into(),
            public_key: sk.verifying_key().as_bytes().to_vec(),
            inner_quorum: inner,
        }
    }

    fn session() -> DkgSession {
        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        DkgSession {
            authority_id: "fta-pharma".into(),
            session_nonce: nonce,
            ceremony_type: "dkg".into(),
        }
    }

    fn pops(
        session: &DkgSession,
        keys: &[(&str, &ed25519_dalek::SigningKey)],
    ) -> Vec<ProofOfPossession> {
        keys.iter()
            .map(|(id, sk)| {
                let pk = sk.verifying_key().as_bytes().to_vec();
                let signature = sk.sign(&session.pop_bytes(id, &pk)).to_bytes().to_vec();
                ProofOfPossession {
                    member: (*id).into(),
                    public_key: pk,
                    signature,
                }
            })
            .collect()
    }

    #[test]
    fn fta_structure_validation() {
        let (a, b, c) = (generate_key(), generate_key(), generate_key());
        let fta = FederatedTrustAuthority {
            id: "fta".into(),
            members: vec![
                org("org-a", &a, Some(Quorum { t: 2, n: 3 })),
                org("org-b", &b, None),
                org("org-c", &c, None),
            ],
            org_quorum: Quorum { t: 2, n: 3 },
            aggregate_key: vec![1],
            hierarchy_spanning: true,
        };
        assert!(fta.validate().is_ok());
        assert_eq!(
            fta.requires_inner_quorum("org-a"),
            Some(Quorum { t: 2, n: 3 })
        );
        assert_eq!(fta.requires_inner_quorum("org-b"), None);

        let mut bad = fta.clone();
        bad.members.push(bad.members[0].clone());
        assert!(bad.validate().is_err());
        let mut badq = fta;
        badq.org_quorum = Quorum { t: 5, n: 3 };
        assert!(badq.validate().is_err());
    }

    #[test]
    fn rogue_key_defense_rejects_forged_pop() {
        let session = session();
        let keys = [("org-a", generate_key()), ("org-b", generate_key())];
        let refs: Vec<(&str, &ed25519_dalek::SigningKey)> =
            keys.iter().map(|(id, sk)| (*id, sk)).collect();
        let mut good = pops(&session, &refs);
        // org-b forges org-a's contribution with its own key.
        let mut forged = good[1].clone();
        forged.member = "org-a".into();
        good[1] = forged;

        let err = session
            .verify_contributions(&good, Quorum { t: 2, n: 2 }, &Ed25519Verifier)
            .unwrap_err();
        assert!(err.to_string().contains("rogue-key"), "got {err}");
    }

    #[test]
    fn dkg_quorum_enforced() {
        let session = session();
        let a = generate_key();
        let keys = [("org-a", &a)];
        let good = pops(&session, &keys);
        // 2-of-2 required but only one contributed.
        assert!(
            session
                .verify_contributions(&good, Quorum { t: 2, n: 2 }, &Ed25519Verifier)
                .is_err()
        );
    }

    #[test]
    fn nonce_commitment_round_trip() {
        let mut nonce = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let c = NonceCommitment::commit("org-a", &nonce);
        assert!(c.verify(&NonceReveal {
            member: "org-a".into(),
            nonce,
        }));
        let mut wrong = nonce;
        wrong[0] ^= 1;
        assert!(!c.verify(&NonceReveal {
            member: "org-a".into(),
            nonce: wrong,
        }));
    }

    #[test]
    fn identifiable_abort_names_the_culprit() {
        let session = session();
        let a = generate_key();
        let b = generate_key();
        let expected = vec![org("org-a", &a, None), org("org-b", &b, None)];
        let keys = [("org-a", &a)];
        let only_a = pops(&session, &keys);
        let err = attribute_dkg_failure(&session, &expected, &only_a, &[], &[], &Ed25519Verifier)
            .unwrap_err();
        assert_eq!(err.faulty_member, "org-b");
        assert_eq!(err.reason, AbortReason::Timeout);

        // Nonce commitment mismatch attributes to the liar (both
        // members contributed PoPs; org-a's reveal contradicts its
        // commitment).
        let both = pops(&session, &[("org-a", &a), ("org-b", &b)]);
        let mut nonce = [7u8; 32];
        let commitment = NonceCommitment::commit("org-a", &nonce);
        nonce[0] ^= 1;
        let reveal = NonceReveal {
            member: "org-a".into(),
            nonce,
        };
        let err = attribute_dkg_failure(
            &session,
            &expected,
            &both,
            &[commitment],
            &[reveal],
            &Ed25519Verifier,
        )
        .unwrap_err();
        assert_eq!(err.reason, AbortReason::NonceCommitmentMismatch);
    }

    #[test]
    fn membership_changes_preserve_aggregate() {
        let key = vec![9u8; 32];
        let join = MembershipChange {
            kind: MembershipChangeKind::Join {
                org: org("org-d", &generate_key(), None),
            },
            aggregate_key_before: key.clone(),
            aggregate_key_after: key.clone(),
        };
        assert!(join.validate().is_ok());

        let leave = MembershipChange {
            kind: MembershipChangeKind::Leave {
                org_id: "org-a".into(),
            },
            aggregate_key_before: key.clone(),
            aggregate_key_after: vec![8u8; 32],
        };
        assert!(leave.validate().is_err());

        let dissolve = MembershipChange {
            kind: MembershipChangeKind::Dissolve,
            aggregate_key_before: key,
            aggregate_key_after: vec![],
        };
        assert!(dissolve.validate().is_ok());
    }
}
