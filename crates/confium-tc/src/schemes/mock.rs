//! Mock threshold-signature scheme — `"mock-tc-sig"`.
//!
//! This is a deterministic, cryptographically meaningless scheme whose
//! only purpose is to exercise the full [`crate::session::Session`]
//! lifecycle (create → round → result) end-to-end. It proves the
//! framework wiring is correct: the registry resolves the scheme, the
//! session drives the rounds, the threshold property holds (any T of N
//! parties produce identical output), and below-threshold coalitions
//! fail.
//!
//! ## Protocol
//!
//! The "shared secret" is a fixed fake key baked into every party's
//! share bytes. The "signature" is a deterministic function of the full
//! party roster plus the signed message — it never depends on *which*
//! coalition produced it, so any T-of-N produces the same bytes.
//!
//! Three rounds:
//!
//! - **Round 0** — broadcast: each party emits its `party_id` plus a
//!   nonce derived deterministically from `(shared_key, party_id,
//!   message)`. Determinism guarantees the nonce set is identical
//!   across coalitions of the same party roster.
//!
//! - **Round 1** — broadcast: each party HMAC-SHA256-signs the sorted
//!   nonce set with the shared key, then broadcasts the tag.
//!
//! - **Round 2** — complete: the party checks that at least T distinct
//!   round-1 tags arrived (threshold enforcement), then rebuilds the
//!   canonical signature by re-deriving every roster party's round-1
//!   tag and concatenating them sorted by `party_id`. Because nonces
//!   and the HMAC key are deterministic, this signature is identical on
//!   every party regardless of coalition.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::Result;
use crate::message::Message;
use crate::registry::{RoundResult, SessionImpl, TcScheme, TcSchemeKind};
use crate::session::SessionParams;

/// Canonical scheme name advertised through the registry.
pub const SCHEME_NAME: &str = "mock-tc-sig";

/// HMAC keyed by the shared secret — the round-1 primitive.
type HmacSha256 = Hmac<Sha256>;

/// Mock threshold-signature scheme.
///
/// Stateless; all per-session state lives in [`MockTcSigSession`].
pub struct MockTcSigScheme;

impl TcScheme for MockTcSigScheme {
    fn name(&self) -> &'static str {
        SCHEME_NAME
    }

    fn kind(&self) -> TcSchemeKind {
        TcSchemeKind::Signature
    }

    fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
        let party_id = params.parties.get(params.this_party_idx)?.id.clone();
        let threshold = params.threshold;
        let message = params.message.clone().unwrap_or_default();
        let roster_ids = params
            .parties
            .parties()
            .iter()
            .map(|p| p.id.clone())
            .collect::<Vec<_>>();
        // The shared secret is the party's share bytes (identical on
        // every party in a real deployment). Default to a fixed
        // well-known key when no share is supplied so tests don't need
        // to fabricate one.
        let shared_key = params
            .local_share
            .as_ref()
            .map(|s| s.bytes().to_vec())
            .unwrap_or_else(|| DEFAULT_SHARED_KEY.to_vec());

        Ok(Box::new(MockTcSigSession {
            party_id,
            threshold,
            roster_ids,
            shared_key,
            message,
            round_done: 0,
            collected_tags: 0,
            signature: Vec::new(),
        }))
    }
}

// Register the scheme at link time so `Session::create("mock-tc-sig")`
// resolves it through the framework registry.
crate::register_tc_scheme!(MockTcSigScheme);

/// The fixed fake "shared secret" used when no share is supplied.
/// Every party in a coalition uses the same key — that is the entire
/// premise of the mock.
const DEFAULT_SHARED_KEY: &[u8] = b"confium-mock-tc-sig-shared-key";

/// Per-party, per-session state for [`MockTcSigScheme`].
struct MockTcSigSession {
    /// Our canonical party id.
    party_id: String,
    /// Threshold T copied from session params.
    threshold: u32,
    /// Full roster of party ids — the canonical signature covers every
    /// one of these, regardless of which coalition ran.
    roster_ids: Vec<String>,
    /// Shared HMAC key (same on every party).
    shared_key: Vec<u8>,
    /// Message being signed.
    message: Vec<u8>,
    /// How many `round` calls have run (0, then 1, 2, 3).
    round_done: u8,
    /// Distinct parties that contributed a round-1 tag. Drives the
    /// threshold check in round 2.
    collected_tags: usize,
    /// Final signature bytes, populated in round 2.
    signature: Vec<u8>,
}

impl MockTcSigSession {
    /// Deterministically derive a party's nonce from the shared key,
    /// its party id, and the message. The nonce is therefore identical
    /// regardless of which coalition this party is part of.
    fn derive_nonce(party_id: &str, shared_key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"mock-tc-sig-nonce");
        hasher.update(shared_key);
        hasher.update(party_id.as_bytes());
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    /// The canonical round-1 blob every party HMACs: the sorted set of
    /// `(party_id, nonce)` pairs from the full roster, followed by the
    /// message. Identical on every party.
    fn canonical_blob(roster_ids: &[String], shared_key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut entries: Vec<(String, Vec<u8>)> = roster_ids
            .iter()
            .map(|id| (id.clone(), Self::derive_nonce(id, shared_key, message)))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut blob = Vec::new();
        for (id, nonce) in &entries {
            blob.extend_from_slice(id.as_bytes());
            blob.extend_from_slice(nonce);
        }
        blob.extend_from_slice(message);
        blob
    }

    /// HMAC-SHA256 tag of the supplied data keyed with the shared secret.
    fn hmac(shared_key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(shared_key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Round 0: emit our nonce as a broadcast. No incoming messages on
    /// the first round.
    fn round0(&mut self) -> Result<RoundResult> {
        let nonce = Self::derive_nonce(&self.party_id, &self.shared_key, &self.message);
        let payload = frame(&self.party_id, &nonce);
        let msg = Message::broadcast(&self.party_id, 1, payload);
        Ok(RoundResult::new(vec![msg], false))
    }

    /// Round 1: compute the HMAC over the canonical nonce set and
    /// broadcast the tag. Incoming nonces are ignored for the tag
    /// computation (determinism makes them redundant) but the round
    /// still consumes the slot in the protocol.
    fn round1(&mut self, _incoming: &[Message]) -> Result<RoundResult> {
        let blob = Self::canonical_blob(&self.roster_ids, &self.shared_key, &self.message);
        let tag = Self::hmac(&self.shared_key, &blob);
        let payload = frame(&self.party_id, &tag);
        let msg = Message::broadcast(&self.party_id, 2, payload);
        Ok(RoundResult::new(vec![msg], false))
    }

    /// Round 2: count distinct contributing parties, enforce the
    /// threshold, and assemble the canonical signature.
    fn round2(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        // Threshold enforcement: count distinct parties that sent a
        // round-1 tag (plus ourselves).
        let mut seen: std::collections::HashSet<String> = parse_frames(incoming)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        seen.insert(self.party_id.clone());
        self.collected_tags = seen.len();

        if (self.collected_tags as u32) < self.threshold {
            return Err(crate::error::SchemeInternalSnafu { code: 0x1042u32 }.build());
        }

        // Canonical signature: every roster party's tag, sorted by id.
        // Independent of the participating coalition.
        let blob = Self::canonical_blob(&self.roster_ids, &self.shared_key, &self.message);
        let tag = Self::hmac(&self.shared_key, &blob);
        let mut sig = Vec::new();
        sig.extend_from_slice(&tag);
        self.signature = sig;
        Ok(RoundResult::done())
    }
}

impl SessionImpl for MockTcSigSession {
    fn round(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        self.round_done = self.round_done.checked_add(1).ok_or_else(|| {
            crate::error::RoundOverflowSnafu {
                round: self.round_done,
            }
            .build()
        })?;
        match self.round_done {
            1 => self.round0(),
            2 => self.round1(incoming),
            3 => self.round2(incoming),
            other => Err(crate::error::RoundOverflowSnafu { round: other }.build()),
        }
    }

    fn result(&self) -> Result<Vec<u8>> {
        if self.round_done < 3 {
            return Err(crate::error::SessionNotCompleteSnafu {}.build());
        }
        Ok(self.signature.clone())
    }

    fn destroy(&mut self) {
        self.shared_key.fill(0);
        self.message.fill(0);
        self.signature.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Wire format helpers — payload framing for the mock scheme's messages.
// ---------------------------------------------------------------------------

/// Frame a payload as `party_id_len:u8 | party_id | body`. Used for
/// both round-0 nonces and round-1 tags since they share the shape.
fn frame(party_id: &str, body: &[u8]) -> Vec<u8> {
    let id = party_id.as_bytes();
    debug_assert!(id.len() <= u8::MAX as usize, "party id fits in a byte tag");
    let mut out = Vec::with_capacity(1 + id.len() + body.len());
    out.push(id.len() as u8);
    out.extend_from_slice(id);
    out.extend_from_slice(body);
    out
}

/// Parse framed payloads back into `(party_id, body)` pairs. Unknown or
/// truncated frames are silently skipped — the mock is forgiving about
/// the incoming shape so the test harness can mix in our own broadcasts.
fn parse_frames(msgs: &[Message]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::with_capacity(msgs.len());
    for m in msgs {
        let p = &m.payload;
        if p.is_empty() {
            continue;
        }
        let len = p[0] as usize;
        if p.len() < 1 + len {
            continue;
        }
        let id = match std::str::from_utf8(&p[1..1 + len]) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };
        out.push((id, p[1 + len..].to_vec()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::party::{Party, PartyList};
    use crate::share::Share;

    fn params(idx: usize, threshold: u32, message: &[u8]) -> SessionParams {
        SessionParams {
            scheme: SCHEME_NAME.to_string(),
            parties: PartyList::from_parties(vec![
                Party::inproc("alice"),
                Party::inproc("bob"),
                Party::inproc("carol"),
            ]),
            threshold,
            this_party_idx: idx,
            local_share: Some(Share::new(SCHEME_NAME, DEFAULT_SHARED_KEY.to_vec())),
            message: Some(message.to_vec()),
        }
    }

    #[test]
    fn scheme_is_registered() {
        let s = crate::registry::find(SCHEME_NAME);
        assert!(s.is_some(), "mock-tc-sig must be registered at link time");
        assert_eq!(s.unwrap().kind(), TcSchemeKind::Signature);
    }

    #[test]
    fn nonce_is_deterministic_per_party() {
        let a = MockTcSigSession::derive_nonce("alice", DEFAULT_SHARED_KEY, b"msg");
        let b = MockTcSigSession::derive_nonce("alice", DEFAULT_SHARED_KEY, b"msg");
        assert_eq!(a, b, "nonce must be deterministic for the same inputs");
    }

    #[test]
    fn nonce_differs_per_party() {
        let a = MockTcSigSession::derive_nonce("alice", DEFAULT_SHARED_KEY, b"msg");
        let b = MockTcSigSession::derive_nonce("bob", DEFAULT_SHARED_KEY, b"msg");
        assert_ne!(a, b, "different parties produce different nonces");
    }

    #[test]
    fn canonical_blob_is_independent_of_roster_order() {
        let mut a = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
        let mut b = vec!["carol".to_string(), "alice".to_string(), "bob".to_string()];
        let blob_a = MockTcSigSession::canonical_blob(&a, DEFAULT_SHARED_KEY, b"msg");
        let blob_b = MockTcSigSession::canonical_blob(&b, DEFAULT_SHARED_KEY, b"msg");
        assert_eq!(blob_a, blob_b, "blob must sort the roster canonically");
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn frame_round_trip() {
        let f = frame("alice", &[1, 2, 3]);
        let parsed = parse_frames(&[Message::broadcast("alice", 1, f.clone())]);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, "alice");
        assert_eq!(parsed[0].1, vec![1, 2, 3]);
    }

    #[test]
    fn parse_skips_truncated() {
        let bad = vec![5, b'a'];
        let parsed = parse_frames(&[Message::broadcast("x", 1, bad)]);
        assert!(parsed.is_empty(), "truncated frame must be skipped");
    }

    #[test]
    fn create_session_uses_default_key_when_no_share() {
        let mut p = params(0, 2, b"msg");
        p.local_share = None;
        let s = MockTcSigScheme.create_session(&p);
        assert!(s.is_ok(), "session creates without a share");
    }
}
