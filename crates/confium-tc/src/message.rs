//! Round message exchanged between parties.
//!
//! A [`Message`] is the unit of communication in a threshold session.
//! Each round, a party emits zero or more [`Message`]s (either
//! broadcast — `to_party_id == None` — or directed to a specific peer)
//! and consumes the [`Message`]s it received from the previous round.
//!
//! The framework is transport-agnostic: it produces and consumes
//! [`Message`]s. Wiring [`Message`]s to a Network transport is a
//! separate concern handled by the session driver (see
//! `TODO.roadmap/05-networking-primitives.md`).

use std::fmt;

/// A single inter-party message belonging to one round of a session.
///
/// `from_party_id` and `to_party_id` are the canonical ASCII party ids
/// from [`crate::party::Party`]. `to_party_id == None` means broadcast
/// — every other party should process this message. `round` is the
/// 1-indexed round number the message belongs to; `payload` is the
/// scheme-specific wire bytes (commitments, signature shares, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub from_party_id: String,
    pub to_party_id: Option<String>,
    pub round: u8,
    pub payload: Vec<u8>,
}

impl Message {
    /// Build a directed (point-to-point) message.
    pub fn directed(
        from: impl Into<String>,
        to: impl Into<String>,
        round: u8,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Message {
            from_party_id: from.into(),
            to_party_id: Some(to.into()),
            round,
            payload: payload.into(),
        }
    }

    /// Build a broadcast message — addressed to every other party.
    pub fn broadcast(from: impl Into<String>, round: u8, payload: impl Into<Vec<u8>>) -> Self {
        Message {
            from_party_id: from.into(),
            to_party_id: None,
            round,
            payload: payload.into(),
        }
    }

    /// True when this message is addressed to every party.
    pub fn is_broadcast(&self) -> bool {
        self.to_party_id.is_none()
    }

    /// True when this message is directed at exactly one party.
    pub fn is_directed(&self) -> bool {
        self.to_party_id.is_some()
    }

    /// True when the message is intended for `party_id` — either a
    /// broadcast or a directed message whose `to_party_id` matches.
    pub fn is_for(&self, party_id: &str) -> bool {
        match &self.to_party_id {
            None => true,
            Some(to) => to == party_id,
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let to = self.to_party_id.as_deref().unwrap_or("*");
        write!(
            f,
            "round {} {} -> {} ({} bytes)",
            self.round,
            self.from_party_id,
            to,
            self.payload.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_message_has_null_recipient() {
        let m = Message::broadcast("node-1", 1, [0xAA, 0xBB]);
        assert!(m.is_broadcast());
        assert!(!m.is_directed());
        assert!(m.to_party_id.is_none());
    }

    #[test]
    fn directed_message_has_recipient() {
        let m = Message::directed("node-1", "node-2", 2, [0x01]);
        assert!(!m.is_broadcast());
        assert!(m.is_directed());
        assert_eq!(m.to_party_id.as_deref(), Some("node-2"));
    }

    #[test]
    fn is_for_matches_directed_recipient() {
        let m = Message::directed("a", "b", 1, []);
        assert!(m.is_for("b"));
        assert!(!m.is_for("a"));
        assert!(!m.is_for("c"));
    }

    #[test]
    fn is_for_matches_everyone_when_broadcast() {
        let m = Message::broadcast("a", 1, []);
        assert!(m.is_for("b"));
        assert!(m.is_for("c"));
        // Broadcast is also "for" the sender per this predicate — the
        // driver layer is responsible for not echoing to self.
        assert!(m.is_for("a"));
    }

    #[test]
    fn display_format_includes_round_and_parties() {
        let m = Message::directed("a", "b", 3, [0u8; 4]);
        assert_eq!(format!("{m}"), "round 3 a -> b (4 bytes)");
    }

    #[test]
    fn display_format_uses_star_for_broadcast() {
        let m = Message::broadcast("a", 1, [0u8; 2]);
        assert_eq!(format!("{m}"), "round 1 a -> * (2 bytes)");
    }

    #[test]
    fn equality_compares_all_fields() {
        let a = Message::directed("p1", "p2", 1, vec![1, 2]);
        let b = Message::directed("p1", "p2", 1, vec![1, 2]);
        assert_eq!(a, b);

        let c = Message::directed("p1", "p2", 2, vec![1, 2]);
        assert_ne!(a, c);

        let d = Message::directed("p1", "p3", 1, vec![1, 2]);
        assert_ne!(a, d);
    }
}
