//! Revocation semantics (SIGNATIF §12).
//!
//! Four pieces:
//!
//! - [`Crl`] — the signed, time-stamped list of revoked authority
//!   credentials with reason, validity period, and a transparency-log
//!   reference for its own publication;
//! - [`AuthorityStateBinding`] — the hash-binding that ties an
//!   artifact to the authority states under which it was produced;
//! - [`RevocationIndex`] — propagation and query: when a state is
//!   revoked, every transitively bound artifact is *marked* (never
//!   deleted), reversibly if the revocation is corrected;
//! - [`RevocationView`] — the offline-verifier lens consumed by the
//!   pipeline, including the CRL grace-period policy.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Default offline CRL grace period before a stale CRL hard-rejects.
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::hours(24);

/// Why a credential was revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Cryptographic key compromise.
    KeyCompromise,
    /// The authority ceased operation or affiliation ended.
    CessationOfOperation,
    /// Issued in error or superseded.
    Superseded,
    /// Withdrawn by the authority (policy).
    Withdrawn,
}

/// One entry in a CRL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedEntry {
    /// Fingerprint of the revoked credential.
    pub fingerprint: String,
    /// When it was revoked.
    pub revoked_at: DateTime<Utc>,
    /// Why.
    pub reason: RevocationReason,
}

/// A certificate revocation list: signed by the issuing trust
/// authority, timestamped, validity-bounded, log-recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crl {
    /// The issuing trust authority's identifier.
    pub issuer: String,
    /// Revoked credentials.
    pub revoked: Vec<RevokedEntry>,
    /// CRL validity start.
    pub this_update: DateTime<Utc>,
    /// CRL validity end.
    pub next_update: DateTime<Utc>,
    /// Transparency-log sequence of this CRL's own publication.
    pub log_sequence: u64,
    /// The issuer's signature over the canonical CRL body.
    pub signature: Vec<u8>,
}

impl Crl {
    /// The canonical signing bytes (JCS of the CRL without signature).
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn signing_bytes(&self) -> crate::error::SignatifResult<Vec<u8>> {
        let mut copy = self.clone();
        copy.signature = Vec::new();
        Ok(
            crate::jcs::canonicalize(&serde_json::to_value(&copy).expect("crl serializes"))?
                .into_bytes(),
        )
    }

    /// Whether the CRL covers `fingerprint` with a revocation time at
    /// or before `at`.
    pub fn revokes(&self, fingerprint: &str, at: DateTime<Utc>) -> Option<&RevokedEntry> {
        self.revoked
            .iter()
            .find(|e| e.fingerprint == fingerprint && e.revoked_at <= at)
    }

    /// Whether the CRL is stale: `now` past `next_update`.
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        now > self.next_update
    }
}

/// The hash-binding of an artifact to the authority states under
/// which it was produced (`hash-binding` requirement): the artifact's
/// canonical payload hash plus the fingerprints of every authority on
/// every verified path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityStateBinding {
    /// The bound artifact's canonical payload hash (hex).
    pub artifact_hash: String,
    /// Fingerprints of authority states the artifact depends on.
    pub authority_fingerprints: Vec<String>,
    /// When the binding was recorded.
    pub bound_at: DateTime<Utc>,
}

/// Revocation status of a signer as seen by the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Not revoked; CRL fresh.
    Good,
    /// Not revoked, but the CRL is within the grace window — soft.
    GraceDowngrade,
    /// Revoked — hard failure.
    Revoked,
}

/// The offline-verifier revocation lens.
pub trait RevocationView {
    /// Status of the authority identified by `id` at time `now`.
    fn authority_status(&self, id: &str, now: DateTime<Utc>) -> RevocationStatus;

    /// Age of the freshest CRL consulted (zero when none exist).
    fn max_crl_age(&self, now: DateTime<Utc>) -> Duration;
}

/// A view with no revocations — for sealed offline bundles with empty
/// CRLs and for tests.
#[derive(Debug, Clone, Copy)]
pub struct NoRevocations;

impl RevocationView for NoRevocations {
    fn authority_status(&self, _id: &str, _now: DateTime<Utc>) -> RevocationStatus {
        RevocationStatus::Good
    }

    fn max_crl_age(&self, _now: DateTime<Utc>) -> Duration {
        Duration::zero()
    }
}

/// A concrete view over a set of CRLs.
#[derive(Debug, Clone, Default)]
pub struct CrlView {
    /// Fingerprints of the authorities whose status is being asked.
    pub authority_fingerprints: BTreeMap<String, String>,
    /// The CRLs held (cached for offline verification).
    pub crls: Vec<Crl>,
}

impl RevocationView for CrlView {
    fn authority_status(&self, id: &str, now: DateTime<Utc>) -> RevocationStatus {
        let Some(fp) = self.authority_fingerprints.get(id) else {
            return RevocationStatus::Good;
        };
        let stale = self.crls.iter().all(|c| c.is_stale(now));
        for crl in &self.crls {
            if crl.revokes(fp, now).is_some() {
                return RevocationStatus::Revoked;
            }
        }
        if stale && !self.crls.is_empty() {
            RevocationStatus::GraceDowngrade
        } else {
            RevocationStatus::Good
        }
    }

    fn max_crl_age(&self, now: DateTime<Utc>) -> Duration {
        self.crls
            .iter()
            .map(|c| now.signed_duration_since(c.this_update))
            .max()
            .unwrap_or_else(Duration::zero)
    }
}

/// Artifact marking: revoked-but-not-deleted, reversible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactMark {
    /// Bound to a revoked authority state.
    Marked,
    /// Mark cleared after a corrected revocation.
    Cleared,
}

/// The propagation and query index: artifacts ↔ authority states.
#[derive(Debug, Clone, Default)]
pub struct RevocationIndex {
    bindings: Vec<AuthorityStateBinding>,
    marks: BTreeMap<String, ArtifactMark>,
    revoked_states: Vec<String>,
}

impl RevocationIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an artifact's binding to authority states.
    pub fn bind(&mut self, binding: AuthorityStateBinding) {
        self.bindings.push(binding);
    }

    /// Revoke an authority state (by fingerprint) and propagate: every
    /// artifact transitively bound to that state is **marked**, not
    /// deleted; the marking is queryable and reversible.
    pub fn revoke_state(&mut self, fingerprint: &str) {
        self.revoked_states.push(fingerprint.to_string());
        for b in &self.bindings {
            if b.authority_fingerprints.iter().any(|f| f == fingerprint) {
                self.marks
                    .insert(b.artifact_hash.clone(), ArtifactMark::Marked);
            }
        }
    }

    /// Correct a revocation: un-mark artifacts bound to the state.
    pub fn correct_state(&mut self, fingerprint: &str) {
        self.revoked_states.retain(|f| f != fingerprint);
        for b in &self.bindings {
            if b.authority_fingerprints.iter().any(|f| f == fingerprint) {
                self.marks
                    .insert(b.artifact_hash.clone(), ArtifactMark::Cleared);
            }
        }
    }

    /// Forward query: the states an artifact is bound to and its
    /// current marking.
    pub fn artifact_status(&self, artifact_hash: &str) -> (Vec<String>, Option<ArtifactMark>) {
        let states = self
            .bindings
            .iter()
            .find(|b| b.artifact_hash == artifact_hash)
            .map(|b| b.authority_fingerprints.clone())
            .unwrap_or_default();
        (states, self.marks.get(artifact_hash).copied())
    }

    /// Reverse query: artifacts bound to a given state.
    pub fn artifacts_for_state(&self, fingerprint: &str) -> Vec<String> {
        self.bindings
            .iter()
            .filter(|b| b.authority_fingerprints.iter().any(|f| f == fingerprint))
            .map(|b| b.artifact_hash.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crl(revoked: Vec<RevokedEntry>) -> Crl {
        Crl {
            issuer: "root".into(),
            revoked,
            this_update: Utc::now() - Duration::hours(1),
            next_update: Utc::now() + Duration::days(7),
            log_sequence: 42,
            signature: vec![],
        }
    }

    #[test]
    fn crl_matches_by_fingerprint_and_time() {
        let fp = "abc";
        let c = crl(vec![RevokedEntry {
            fingerprint: fp.into(),
            revoked_at: Utc::now() - Duration::minutes(5),
            reason: RevocationReason::KeyCompromise,
        }]);
        assert!(c.revokes(fp, Utc::now()).is_some());
        assert!(c.revokes(fp, Utc::now() - Duration::hours(1)).is_none());
        assert!(c.revokes("other", Utc::now()).is_none());
    }

    #[test]
    fn view_reports_revoked_and_stale_grace() {
        let fp = "abc";
        let mut view = CrlView::default();
        view.authority_fingerprints.insert("end".into(), fp.into());
        view.crls.push(crl(vec![RevokedEntry {
            fingerprint: fp.into(),
            revoked_at: Utc::now(),
            reason: RevocationReason::Withdrawn,
        }]));
        assert_eq!(
            view.authority_status("end", Utc::now()),
            RevocationStatus::Revoked
        );

        let fresh_view = CrlView {
            authority_fingerprints: [("end".to_string(), "abc".to_string())]
                .into_iter()
                .collect(),
            crls: vec![crl(vec![])],
        };
        assert_eq!(
            fresh_view.authority_status("end", Utc::now()),
            RevocationStatus::Good
        );

        let mut stale = fresh_view.clone();
        stale.crls[0].next_update = Utc::now() - Duration::hours(1);
        assert_eq!(
            stale.authority_status("end", Utc::now()),
            RevocationStatus::GraceDowngrade
        );
    }

    #[test]
    fn propagation_marks_reversibly() {
        let mut idx = RevocationIndex::new();
        idx.bind(AuthorityStateBinding {
            artifact_hash: "h1".into(),
            authority_fingerprints: vec!["fp-root".into(), "fp-end".into()],
            bound_at: Utc::now(),
        });
        idx.bind(AuthorityStateBinding {
            artifact_hash: "h2".into(),
            authority_fingerprints: vec!["fp-other".into()],
            bound_at: Utc::now(),
        });

        idx.revoke_state("fp-end");
        assert_eq!(idx.artifact_status("h1").1, Some(ArtifactMark::Marked));
        assert_eq!(idx.artifact_status("h2").1, None);
        assert_eq!(idx.artifacts_for_state("fp-end"), vec!["h1".to_string()]);

        idx.correct_state("fp-end");
        assert_eq!(idx.artifact_status("h1").1, Some(ArtifactMark::Cleared));
    }
}
