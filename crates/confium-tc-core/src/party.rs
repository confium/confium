//! Party identity and the roster of participants in a threshold session.
//!
//! A threshold protocol runs between N parties. Each party has a stable
//! identifier (a short ASCII handle, opaque to the framework) and, for
//! networked sessions, a transport endpoint URL. The framework itself
//! treats party IDs as uninterpreted strings — scheme-specific encoding
//! (e.g. a numeric index, a public-key fingerprint) is the plugin's job.
//!
//! See `TODO.roadmap/04-threshold-cryptography.md` for the design and
//! `TODO.roadmap/05-networking-primitives.md` for the transport contract.

use std::fmt;

use snafu::ensure;

use crate::Result;
use crate::error;

/// One participant in a threshold session.
///
/// `id` is the canonical ASCII name used as `from_party_id` /
/// `to_party_id` in [`crate::message::Message`]. `transport_endpoint` is
/// a URL the Network pillar can connect to (e.g.
/// `quic://node1.example.com:443`); it may be `None` for in-process
/// sessions where the framework routes messages directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Party {
    pub id: String,
    pub transport_endpoint: Option<String>,
}

impl Party {
    pub fn new(id: impl Into<String>, transport_endpoint: Option<String>) -> Self {
        Party {
            id: id.into(),
            transport_endpoint,
        }
    }

    /// Build a party with no network endpoint — useful for in-process
    /// simulation harnesses.
    pub fn inproc(id: impl Into<String>) -> Self {
        Party {
            id: id.into(),
            transport_endpoint: None,
        }
    }
}

/// Ordered roster of parties for a session.
///
/// The ordering defines each party's index, which `cfm_tc_session_create`
/// receives as `this_party_idx`. The threshold T is tracked separately on
/// [`crate::session::Session`] — a [`PartyList`] is purely the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyList {
    parties: Vec<Party>,
}

impl PartyList {
    pub fn new() -> Self {
        PartyList {
            parties: Vec::new(),
        }
    }

    pub fn from_parties(parties: Vec<Party>) -> Self {
        PartyList { parties }
    }

    pub fn parties(&self) -> &[Party] {
        &self.parties
    }

    pub fn len(&self) -> usize {
        self.parties.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parties.is_empty()
    }

    pub fn push(&mut self, party: Party) {
        self.parties.push(party);
    }

    /// Fetch the party at `idx`, returning [`error::Error::PartyIndexOutOfRange`]
    /// when out of bounds.
    pub fn get(&self, idx: usize) -> Result<&Party> {
        self.parties.get(idx).ok_or_else(|| {
            error::PartyIndexOutOfRangeSnafu {
                idx,
                count: self.parties.len(),
            }
            .build()
        })
    }

    /// Look up a party by canonical id.
    pub fn find(&self, id: &str) -> Option<&Party> {
        self.parties.iter().find(|p| p.id == id)
    }

    /// Validate the roster for use in a session with the given threshold:
    /// at least one party, no duplicate ids, and threshold in range.
    pub fn validate(&self, threshold: u32) -> Result<()> {
        ensure!(!self.parties.is_empty(), error::EmptyPartyListSnafu {});
        ensure!(threshold >= 1, error::ThresholdTooSmallSnafu { threshold });
        ensure!(
            threshold as usize <= self.parties.len(),
            error::ThresholdTooLargeSnafu {
                threshold,
                party_count: self.parties.len(),
            }
        );
        for (i, p) in self.parties.iter().enumerate() {
            for q in &self.parties[i + 1..] {
                ensure!(p.id != q.id, error::DuplicatePartyIdSnafu { id: &p.id });
            }
        }
        Ok(())
    }
}

impl Default for PartyList {
    fn default() -> Self {
        PartyList::new()
    }
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.transport_endpoint {
            Some(ep) => write!(f, "{}@{}", self.id, ep),
            None => write!(f, "{}", self.id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn party_inproc_has_no_endpoint() {
        let p = Party::inproc("node-1");
        assert_eq!(p.id, "node-1");
        assert!(p.transport_endpoint.is_none());
        assert_eq!(format!("{p}"), "node-1");
    }

    #[test]
    fn party_display_with_endpoint() {
        let p = Party::new("node-1", Some("quic://h:443".to_string()));
        assert_eq!(format!("{p}"), "node-1@quic://h:443");
    }

    #[test]
    fn party_list_get_out_of_range_errors() {
        let list = PartyList::from_parties(vec![Party::inproc("a")]);
        let err = list.get(5).unwrap_err();
        assert!(
            matches!(
                err,
                error::Error::PartyIndexOutOfRange {
                    idx: 5,
                    count: 1,
                    ..
                }
            ),
            "expected PartyIndexOutOfRange, got {err:?}"
        );
    }

    #[test]
    fn party_list_validate_rejects_empty() {
        let list = PartyList::new();
        assert!(list.validate(1).is_err());
    }

    #[test]
    fn party_list_validate_rejects_zero_threshold() {
        let list = PartyList::from_parties(vec![Party::inproc("a"), Party::inproc("b")]);
        let err = list.validate(0).unwrap_err();
        assert!(matches!(
            err,
            error::Error::ThresholdTooSmall { threshold: 0, .. }
        ));
    }

    #[test]
    fn party_list_validate_rejects_threshold_above_party_count() {
        let list = PartyList::from_parties(vec![Party::inproc("a"), Party::inproc("b")]);
        let err = list.validate(3).unwrap_err();
        assert!(matches!(
            err,
            error::Error::ThresholdTooLarge {
                threshold: 3,
                party_count: 2,
                ..
            }
        ));
    }

    #[test]
    fn party_list_validate_rejects_duplicate_ids() {
        let list = PartyList::from_parties(vec![Party::inproc("a"), Party::inproc("a")]);
        let err = list.validate(1).unwrap_err();
        assert!(matches!(err, error::Error::DuplicatePartyId { .. }));
    }

    #[test]
    fn party_list_validate_accepts_valid_roster() {
        let list = PartyList::from_parties(vec![
            Party::inproc("a"),
            Party::inproc("b"),
            Party::inproc("c"),
        ]);
        list.validate(2).expect("valid roster should pass");
    }

    #[test]
    fn party_list_find_by_id() {
        let list = PartyList::from_parties(vec![Party::inproc("a"), Party::inproc("b")]);
        assert_eq!(list.find("b").map(|p| p.id.as_str()), Some("b"));
        assert!(list.find("z").is_none());
    }
}
