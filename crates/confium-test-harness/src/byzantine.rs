//! Byzantine peer behavior simulation.
//!
//! The harness wraps the in-process transport with a
//! [`ByzantineTransport`] that intercepts every [`Message`] flowing
//! between parties and applies the configured [`PeerBehavior`] for the
//! sender. This is what NIST uses to probe a candidate scheme's fault
//! tolerance: does it complete, or does it abort with a proof of
//! misbehavior?
//!
//! Behaviors are keyed by party id (the same canonical id used in
//! `confium-tc::party::Party`). A sender with no configured behavior is
//! treated as [`PeerBehavior::Honest`].
//!
//! The wrapper is transport-agnostic: it operates on [`Message`] values
//! that the runner hands it. Wiring it to a `confium-net::Transport`
//! byte stream is the runner's job (it serializes each `Message` before
//! send and deserializes on recv); this layer sees the structured
//! [`Message`] and decides what (if anything) to forward.

use std::collections::HashMap;

use confium_tc::Message;

/// What a single party does to its outgoing messages.
///
/// Mirrors the `type` strings from the test vector schema in
/// `TODO.roadmap/09-nist-evaluation-harness.md`:
///
/// - `honest` — pass messages through unchanged
/// - `byzantine-drop` — silently drop all messages from one round
/// - `byzantine-tamper` — flip a bit in every payload
/// - `byzantine-replay` — duplicate the previous round's messages
/// - `byzantine-malicious` — substitute a crafted payload
/// - `byzantine-collusion` — alias for `malicious`; the runner treats
///   any group of N-1 colluding peers as N-1 individual malicious
///   senders
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerBehavior {
    Honest,
    Drop,
    Tamper,
    Replay,
    Malicious,
    Collusion,
}

impl PeerBehavior {
    /// Map a vector's `type = "..."` string to a behavior. Returns
    /// `None` for an unknown tag so the vector parser can surface a
    /// clear error.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "honest" => Some(PeerBehavior::Honest),
            "byzantine-drop" => Some(PeerBehavior::Drop),
            "byzantine-tamper" => Some(PeerBehavior::Tamper),
            "byzantine-replay" => Some(PeerBehavior::Replay),
            "byzantine-malicious" => Some(PeerBehavior::Malicious),
            "byzantine-collusion" => Some(PeerBehavior::Collusion),
            _ => None,
        }
    }

    /// The canonical vector tag for this behavior.
    pub fn as_tag(self) -> &'static str {
        match self {
            PeerBehavior::Honest => "honest",
            PeerBehavior::Drop => "byzantine-drop",
            PeerBehavior::Tamper => "byzantine-tamper",
            PeerBehavior::Replay => "byzantine-replay",
            PeerBehavior::Malicious => "byzantine-malicious",
            PeerBehavior::Collusion => "byzantine-collusion",
        }
    }
}

/// One entry in a vector's `[[peer_behavior]]` array: which party, and
/// what they do. `drop_round` selects the round a `byzantine-drop`
/// party goes silent in (`None` = drop in round 1, which is the
/// spec's default example).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorSpec {
    pub party_id: String,
    pub behavior: PeerBehavior,
    /// Round to drop messages in (Drop behavior only). Defaults to 1.
    pub drop_round: Option<u8>,
}

/// Message-level interceptor that applies per-party behaviors.
///
/// Construct with [`ByzantineTransport::new`] (or
/// [`ByzantineTransport::from_specs`]) and call
/// [`ByzantineTransport::route`] with each batch of outgoing messages
/// for one round. The returned `Vec<Message>` is what the recipients
/// actually see.
///
/// The wrapper owns a small per-party history so the `Replay` behavior
/// can resurface the previous round's traffic.
#[derive(Debug, Default)]
pub struct ByzantineTransport {
    behaviors: HashMap<String, BehaviorSpec>,
    /// Last round of messages each party sent, for `Replay`.
    last_sent: HashMap<String, Vec<Message>>,
}

impl ByzantineTransport {
    pub fn new() -> Self {
        ByzantineTransport::default()
    }

    pub fn from_specs(specs: Vec<BehaviorSpec>) -> Self {
        let mut behaviors = HashMap::new();
        for spec in specs {
            behaviors.insert(spec.party_id.clone(), spec);
        }
        ByzantineTransport {
            behaviors,
            last_sent: HashMap::new(),
        }
    }

    /// Configure (or replace) the behavior for `party_id`.
    pub fn set(&mut self, spec: BehaviorSpec) {
        self.behaviors.insert(spec.party_id.clone(), spec);
    }

    /// Look up the configured behavior for a party; defaults to Honest.
    pub fn behavior_for(&self, party_id: &str) -> PeerBehavior {
        self.behaviors
            .get(party_id)
            .map(|s| s.behavior)
            .unwrap_or(PeerBehavior::Honest)
    }

    /// Apply every party's behavior to a batch of outgoing messages
    /// from one round, returning the messages recipients will actually
    /// observe. Ordering is preserved within each party's contribution.
    pub fn route(&mut self, outgoing: &[Message]) -> Vec<Message> {
        // Group by sender so each party's behavior sees its own prior
        // round as a unit.
        let mut by_sender: HashMap<&str, Vec<&Message>> = HashMap::new();
        for msg in outgoing {
            by_sender
                .entry(msg.from_party_id.as_str())
                .or_default()
                .push(msg);
        }

        let mut delivered = Vec::with_capacity(outgoing.len());
        for (sender, msgs) in by_sender {
            let behavior = self.behavior_for(sender);
            // Stash this round's honest view for next round's replay
            // before we consume `msgs`.
            let honest_view: Vec<Message> = msgs.iter().map(|m| (*m).clone()).collect();
            let delivered_for_sender = match behavior {
                PeerBehavior::Honest => honest_view.clone(),
                PeerBehavior::Drop => {
                    let spec = self.behaviors.get(sender);
                    let target_round = spec.and_then(|s| s.drop_round).unwrap_or(1);
                    if msgs.iter().any(|m| m.round == target_round) {
                        // This round is the drop target — emit nothing.
                        Vec::new()
                    } else {
                        honest_view.clone()
                    }
                }
                PeerBehavior::Tamper => msgs.iter().map(|m| tamper_message(m)).collect::<Vec<_>>(),
                PeerBehavior::Malicious | PeerBehavior::Collusion => msgs
                    .iter()
                    .map(|m| malicious_message(m))
                    .collect::<Vec<_>>(),
                PeerBehavior::Replay => {
                    if let Some(prev) = self.last_sent.get(sender) {
                        prev.clone()
                    } else {
                        // First round: nothing to replay, fall through
                        // honest so the protocol can at least start.
                        honest_view.clone()
                    }
                }
            };
            self.last_sent.insert(sender.to_string(), honest_view);
            delivered.extend(delivered_for_sender);
        }
        delivered
    }
}

/// Flip the low bit of the first payload byte. Empty payloads stay
/// empty (nothing to tamper with) — schemes that care will reject the
/// resulting malformed message.
fn tamper_message(msg: &Message) -> Message {
    let mut payload = msg.payload.clone();
    if !payload.is_empty() {
        payload[0] ^= 0x01;
    }
    Message {
        from_party_id: msg.from_party_id.clone(),
        to_party_id: msg.to_party_id.clone(),
        round: msg.round,
        payload,
    }
}

/// Substitute a recognizable bogus payload so a correct scheme rejects
/// the message. We keep the envelope (from/to/round) so the harness can
/// attribute the misbehavior to the right party.
fn malicious_message(msg: &Message) -> Message {
    Message {
        from_party_id: msg.from_party_id.clone(),
        to_party_id: msg.to_party_id.clone(),
        round: msg.round,
        payload: b"BYZANTINE-MALICIOUS-PAYLOAD".to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(from: &str, to: Option<&str>, round: u8, payload: &[u8]) -> Message {
        Message {
            from_party_id: from.to_string(),
            to_party_id: to.map(|s| s.to_string()),
            round,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn honest_passes_through_unchanged() {
        let mut tport = ByzantineTransport::new();
        tport.set(BehaviorSpec {
            party_id: "alice".into(),
            behavior: PeerBehavior::Honest,
            drop_round: None,
        });
        let m = msg("alice", None, 1, &[0xAA, 0xBB]);
        let out = tport.route(std::slice::from_ref(&m));
        assert_eq!(out, vec![m]);
    }

    #[test]
    fn unconfigured_party_defaults_honest() {
        let mut tport = ByzantineTransport::new();
        let m = msg("ghost", None, 1, &[1]);
        let out = tport.route(std::slice::from_ref(&m));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, vec![1]);
    }

    #[test]
    fn drop_actually_drops_target_round() {
        let mut tport = ByzantineTransport::new();
        tport.set(BehaviorSpec {
            party_id: "eve".into(),
            behavior: PeerBehavior::Drop,
            drop_round: Some(2),
        });
        // Round 1 — passes.
        let r1 = msg("eve", None, 1, &[10]);
        assert_eq!(tport.route(&[r1]).len(), 1);
        // Round 2 — dropped.
        let r2 = msg("eve", None, 2, &[20]);
        assert!(
            tport.route(&[r2]).is_empty(),
            "round-2 message must be dropped"
        );
        // Round 3 — passes again.
        let r3 = msg("eve", None, 3, &[30]);
        assert_eq!(tport.route(&[r3]).len(), 1);
    }

    #[test]
    fn drop_defaults_to_round_one_when_unspecified() {
        let mut tport = ByzantineTransport::new();
        tport.set(BehaviorSpec {
            party_id: "eve".into(),
            behavior: PeerBehavior::Drop,
            drop_round: None,
        });
        let r1 = msg("eve", None, 1, &[1]);
        assert!(tport.route(&[r1]).is_empty());
    }

    #[test]
    fn tamper_flips_a_bit() {
        let mut tport = ByzantineTransport::new();
        tport.set(BehaviorSpec {
            party_id: "mallory".into(),
            behavior: PeerBehavior::Tamper,
            drop_round: None,
        });
        let original = msg("mallory", None, 1, &[0b0000_0000, 0xFF]);
        let out = tport.route(std::slice::from_ref(&original));
        assert_eq!(out.len(), 1);
        // First byte flipped, second untouched.
        assert_eq!(out[0].payload, vec![0b0000_0001, 0xFF]);
        assert_ne!(out[0].payload, original.payload);
    }

    #[test]
    fn tamper_leaves_empty_payload_untouched() {
        let mut tport = ByzantineTransport::from_specs(vec![BehaviorSpec {
            party_id: "m".into(),
            behavior: PeerBehavior::Tamper,
            drop_round: None,
        }]);
        let empty = msg("m", None, 1, &[]);
        let out = tport.route(std::slice::from_ref(&empty));
        assert!(out[0].payload.is_empty());
    }

    #[test]
    fn malicious_substitutes_payload() {
        let mut tport = ByzantineTransport::new();
        tport.set(BehaviorSpec {
            party_id: "mallory".into(),
            behavior: PeerBehavior::Malicious,
            drop_round: None,
        });
        let original = msg("mallory", Some("alice"), 2, &[0xDE, 0xAD]);
        let out = tport.route(&[original]);
        assert_eq!(out[0].payload, b"BYZANTINE-MALICIOUS-PAYLOAD");
        // Envelope preserved so attribution still works.
        assert_eq!(out[0].from_party_id, "mallory");
        assert_eq!(out[0].to_party_id.as_deref(), Some("alice"));
        assert_eq!(out[0].round, 2);
    }

    #[test]
    fn collusion_behaves_like_malicious() {
        let mut tport = ByzantineTransport::from_specs(vec![BehaviorSpec {
            party_id: "c".into(),
            behavior: PeerBehavior::Collusion,
            drop_round: None,
        }]);
        let out = tport.route(&[msg("c", None, 1, &[0x01])]);
        assert_eq!(out[0].payload, b"BYZANTINE-MALICIOUS-PAYLOAD");
    }

    #[test]
    fn replay_re_sends_previous_round() {
        let mut tport = ByzantineTransport::new();
        tport.set(BehaviorSpec {
            party_id: "ralph".into(),
            behavior: PeerBehavior::Replay,
            drop_round: None,
        });
        // Round 1: nothing cached, falls back honest.
        let r1 = msg("ralph", None, 1, &[11]);
        let out1 = tport.route(std::slice::from_ref(&r1));
        assert_eq!(out1, vec![r1.clone()]);
        // Round 2: replays round 1.
        let r2 = msg("ralph", None, 2, &[22]);
        let out2 = tport.route(&[r2]);
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].payload, vec![11]);
        assert_eq!(out2[0].round, 1, "replayed message keeps old round number");
    }

    #[test]
    fn behavior_round_trips_through_tags() {
        for behavior in [
            PeerBehavior::Honest,
            PeerBehavior::Drop,
            PeerBehavior::Tamper,
            PeerBehavior::Replay,
            PeerBehavior::Malicious,
            PeerBehavior::Collusion,
        ] {
            let tag = behavior.as_tag();
            assert_eq!(PeerBehavior::from_tag(tag), Some(behavior));
        }
    }

    #[test]
    fn unknown_tag_yields_none() {
        assert!(PeerBehavior::from_tag("byzantine-shenanigans").is_none());
    }
}
