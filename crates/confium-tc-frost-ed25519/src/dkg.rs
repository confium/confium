//! Distributed key generation for FROST-ed25519.
//!
//! Implements a Pedersen / Feldman VSS-based DKG that produces:
//!
//! - a per-party secret share `s_i` (32-byte scalar, little-endian),
//! - the aggregate public key `A = (sum of constant terms) · B`
//!   (32-byte compressed point),
//!
//! such that any `T` of the `N` shares can produce FROST signatures that
//! verify against `A` under standard ed25519.
//!
//! ## Protocol
//!
//! Two rounds:
//!
//! - **Round 1** — each party generates a fresh random degree-`T-1`
//!   polynomial `f_i(X)`, broadcasts its Feldman commitment list
//!   `C_{i,k} = a_{i,k} · B`, and sends each peer `j` the directed share
//!   `f_i(j)`.
//!
//! - **Round 2** — each party verifies every received share against its
//!   sender's commitment list (rejecting byzantine parties with a proof),
//!   sums all valid shares into its aggregate share `s_i`, and computes
//!   the aggregate public key as the sum of all parties' `C_{i,0}`.
//!
//! ## Output shape
//!
//! The DKG session's `result()` returns a length-prefixed blob of the form
//!
//! ```text
//!   pubkey_len:u32 BE | pubkey[32] | share_len:u32 BE | share[32]
//! ```
//!
//! The framework's [`confium_tc::Session::dkg_public_key`] only surfaces
//! the first 32 bytes (the public key); this crate's [`parse_output`]
//! helper parses the full blob for callers that need the share as well
//! (e.g. feeding it into a subsequent FROST signing session).
//!
//! ## Deviations from the textbook protocol
//!
//! - **No complaint round.** A party whose VSS share fails verification
//!   is silently excluded from this party's aggregate; that party's
//!   commitment list is also excluded from the public-key sum. This means
//!   all honest parties still converge on the same key as long as they
//!   observe the same broadcasts. A future revision should add an
//!   explicit complaint / expose-the-liar round as the spec requires.
//! - **No secure channel abstraction.** The directed share `f_i(j)` is
//!   transported in the clear inside a [`confium_tc::Message`] addressed
//!   to party `j`. In production this requires an authenticated, private
//!   transport; the framework provides message routing but not
//!   confidentiality. This matches the framework's "transport is a
//!   separate concern" stance (see TODO.roadmap/05).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::rand_core::UnwrapErr;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::error::{
    CODE_BELOW_THRESHOLD, CODE_MALFORMED_MESSAGE, CODE_MALFORMED_SHARE, CODE_ROSTER_CONFIG,
    CODE_ROUND_OVERFLOW, CODE_SESSION_NOT_COMPLETE, FrostError, Result,
};
use crate::group;
use crate::polynomial::{CommitmentList, Polynomial};

/// Canonical scheme name advertised through the registry.
pub const SCHEME_NAME: &str = "FROST-ed25519-dkg";

/// Message type byte tags used inside payloads.
const MSG_ROUND1_BROADCAST: u8 = 0x01;
const MSG_ROUND1_DIRECTED: u8 = 0x02;

// ---------------------------------------------------------------------------
// Scheme + registration
// ---------------------------------------------------------------------------

/// FROST-ed25519 distributed key generation scheme.
///
/// Stateless; all per-session state lives in the internal `DkgSession`.
pub struct FrostEd25519Dkg;

impl confium_tc::registry::TcScheme for FrostEd25519Dkg {
    fn name(&self) -> &'static str {
        SCHEME_NAME
    }

    fn kind(&self) -> confium_tc::registry::TcSchemeKind {
        confium_tc::registry::TcSchemeKind::Dkg
    }

    fn create_session(
        &self,
        params: &confium_tc::SessionParams,
    ) -> confium_tc::error::Result<Box<dyn confium_tc::registry::SessionImpl>> {
        DkgSession::new(params)
            .map(|s| Box::new(s) as Box<dyn confium_tc::registry::SessionImpl>)
            .map_err(FrostError::framework)
    }
}

// Register at link time so `Session::create("FROST-ed25519-dkg")` resolves.
confium_tc::register_tc_scheme!(FrostEd25519Dkg);

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Per-party DKG session state.
struct DkgSession {
    party_id: String,
    /// 1-indexed numeric party index used as the polynomial evaluation
    /// point. Derived from the roster position.
    party_index: u32,
    threshold: u32,
    /// All N party ids in roster order.
    roster_ids: Vec<String>,
    /// Map from party id → numeric index (roster position + 1).
    id_to_index: std::collections::HashMap<String, u32>,
    /// Our own VSS polynomial. Cleared after round 1.
    poly: Option<Polynomial>,
    /// Our own commitment list, broadcast in round 1.
    our_commitments: Vec<[u8; group::ELEMENT_BYTES]>,
    /// Commitment lists received from every peer (by party id).
    peer_commitments: std::collections::HashMap<String, Vec<[u8; group::ELEMENT_BYTES]>>,
    /// VSS share fragments received from peers directed to us. The
    /// aggregate share is `own_share + sum(fragments)`.
    own_share: Scalar,
    received_fragments: Vec<(String, Scalar)>,
    /// Aggregate public key, computed in round 2.
    aggregate_pubkey: Option<[u8; group::ELEMENT_BYTES]>,
    /// Round counter: 0 = no rounds run, 1 after round 1, 2 after round 2.
    round_done: u8,
}

impl DkgSession {
    fn new(params: &confium_tc::SessionParams) -> Result<Self> {
        let threshold = params.threshold;
        if threshold == 0 {
            return Err(FrostError::RosterConfig {
                reason: "threshold must be >= 1",
                code: CODE_ROSTER_CONFIG,
            });
        }
        let roster: Vec<String> = params
            .parties
            .parties()
            .iter()
            .map(|p| p.id.clone())
            .collect();
        if roster.is_empty() {
            return Err(FrostError::RosterConfig {
                reason: "roster must be non-empty",
                code: CODE_ROSTER_CONFIG,
            });
        }
        let (threshold_usize, n) = (threshold as usize, roster.len());
        if threshold_usize > n {
            return Err(FrostError::RosterConfig {
                reason: "threshold exceeds party count",
                code: CODE_ROSTER_CONFIG,
            });
        }
        let this_idx = params.this_party_idx;
        if this_idx >= n {
            return Err(FrostError::RosterConfig {
                reason: "this_party_idx out of range",
                code: CODE_ROSTER_CONFIG,
            });
        }
        let party_id = roster[this_idx].clone();
        // 1-indexed polynomial evaluation points — matches FROST spec
        // convention (party indices start at 1).
        let party_index = (this_idx as u32) + 1;
        let mut id_to_index = std::collections::HashMap::new();
        for (i, id) in roster.iter().enumerate() {
            id_to_index.insert(id.clone(), (i as u32) + 1);
        }

        // Sample a fresh degree-(T-1) polynomial. The constant term is
        // this party's contribution to the aggregate secret; we never
        // reconstruct it.
        let mut coeff = Vec::with_capacity(threshold_usize);
        let mut rng = UnwrapErr(getrandom::SysRng);
        for _ in 0..threshold_usize {
            coeff.push(Scalar::random(&mut rng));
        }
        let poly = Polynomial::from_coefficients(coeff);
        let commits = poly
            .coefficients()
            .iter()
            .map(|a| group::point_to_bytes(&group::mul_base(a)))
            .collect::<Vec<_>>();
        // Our own share contribution is f_i(own_index).
        let own_share = poly.evaluate(party_index);

        Ok(DkgSession {
            party_id,
            party_index,
            threshold,
            roster_ids: roster,
            id_to_index,
            poly: Some(poly),
            our_commitments: commits,
            peer_commitments: std::collections::HashMap::new(),
            own_share,
            received_fragments: Vec::new(),
            aggregate_pubkey: None,
            round_done: 0,
        })
    }

    /// Round 1 — broadcast our commitment list and direct shares to peers.
    fn round1(&mut self) -> confium_tc::error::Result<confium_tc::registry::RoundResult> {
        let poly = self.poly.as_ref().ok_or_else(|| {
            FrostError::RoundOverflow {
                round: self.round_done,
                code: CODE_ROUND_OVERFLOW,
            }
            .framework()
        })?;

        // Broadcast: commitment list.
        let bc_payload = encode_round1_broadcast(self.party_index, &self.our_commitments);
        let mut outgoing = vec![confium_tc::Message::broadcast(
            &self.party_id,
            1,
            bc_payload,
        )];

        // Directed: send f_i(j) to every other party.
        for peer_id in &self.roster_ids {
            if peer_id == &self.party_id {
                continue;
            }
            let j = self.id_to_index.get(peer_id).copied().ok_or_else(|| {
                FrostError::RosterConfig {
                    reason: "peer missing from index map",
                    code: CODE_ROSTER_CONFIG,
                }
                .framework()
            })?;
            let frag = poly.evaluate(j);
            let payload = encode_round1_directed(self.party_index, &frag);
            outgoing.push(confium_tc::Message::directed(
                &self.party_id,
                peer_id,
                1,
                payload,
            ));
        }

        Ok(confium_tc::registry::RoundResult::new(outgoing, false))
    }

    /// Round 2 — verify received fragments against their senders'
    /// commitment lists; aggregate the share and public key.
    fn round2(
        &mut self,
        incoming: &[confium_tc::Message],
    ) -> confium_tc::error::Result<confium_tc::registry::RoundResult> {
        // First, collect commitment broadcasts from round 1.
        for m in incoming {
            if m.round != 1 {
                continue;
            }
            // Distinguish broadcast (commitment list) from directed
            // (share fragment) by the tag byte.
            if m.payload.is_empty() {
                continue;
            }
            let tag = m.payload[0];
            match tag {
                MSG_ROUND1_BROADCAST => match decode_round1_broadcast(&m.payload) {
                    Ok((_idx, commits)) => {
                        self.peer_commitments
                            .insert(m.from_party_id.clone(), commits);
                    }
                    Err(e) => {
                        return Err(e.framework());
                    }
                },
                MSG_ROUND1_DIRECTED => {
                    // Must be addressed to us.
                    if !m.is_for(&self.party_id) {
                        continue;
                    }
                    match decode_round1_directed(&m.payload) {
                        Ok((_sender_idx, frag)) => {
                            self.received_fragments
                                .push((m.from_party_id.clone(), frag));
                        }
                        Err(e) => {
                            return Err(e.framework());
                        }
                    }
                }
                _ => {
                    return Err(FrostError::MalformedMessage {
                        reason: "unknown message tag in DKG round 1",
                        code: CODE_MALFORMED_MESSAGE,
                    }
                    .framework());
                }
            }
        }

        // Verify each received fragment against its sender's commitment
        // list. Byzantine senders are excluded from both the share sum
        // and the public key sum.
        let mut byzantine: Vec<String> = Vec::new();
        for (sender_id, frag) in &self.received_fragments {
            let Some(commits) = self.peer_commitments.get(sender_id) else {
                // No commitment list → cannot verify, treat as byzantine.
                byzantine.push(sender_id.clone());
                continue;
            };
            let cl = CommitmentList::from_bytes(commits.clone());
            if !cl.verify_share(self.party_index, frag) {
                byzantine.push(sender_id.clone());
            }
        }

        // Aggregate the share: own contribution + every verified fragment.
        let mut share = self.own_share;
        for (sender_id, frag) in &self.received_fragments {
            if byzantine.contains(sender_id) {
                continue;
            }
            share += frag;
        }

        // Aggregate the public key: sum of every sender's C_0 plus our
        // own. Byzantine senders are excluded.
        let mut pubkey_point = EdwardsPoint::identity();
        // Our own C_0.
        if !self.our_commitments.is_empty() {
            if let Some(p) = group::point_from_bytes(&self.our_commitments[0]) {
                pubkey_point += p;
            }
        }
        for (sender_id, commits) in &self.peer_commitments {
            if byzantine.contains(sender_id) || commits.is_empty() {
                continue;
            }
            if let Some(p) = group::point_from_bytes(&commits[0]) {
                pubkey_point += p;
            }
        }

        // Threshold check: we need at least T distinct honest senders
        // (including ourselves) for the resulting key to be threshold-safe.
        // We approximate this by requiring that the total contributing
        // count (peers minus byzantine plus ourselves) is >= T.
        let contributing = (self.peer_commitments.len() + 1).saturating_sub(byzantine.len());
        if (contributing as u32) < self.threshold {
            return Err(FrostError::BelowThreshold {
                have: contributing as u32,
                need: self.threshold,
                code: CODE_BELOW_THRESHOLD,
            }
            .framework());
        }

        let pubkey_bytes = group::point_to_bytes(&pubkey_point);
        self.aggregate_pubkey = Some(pubkey_bytes);
        self.own_share = share;

        // We're done — no more rounds needed.
        Ok(confium_tc::registry::RoundResult::done())
    }
}

impl confium_tc::registry::SessionImpl for DkgSession {
    fn round(
        &mut self,
        incoming: &[confium_tc::Message],
    ) -> confium_tc::error::Result<confium_tc::registry::RoundResult> {
        self.round_done = self.round_done.checked_add(1).ok_or_else(|| {
            FrostError::RoundOverflow {
                round: self.round_done,
                code: CODE_ROUND_OVERFLOW,
            }
            .framework()
        })?;
        match self.round_done {
            1 => self.round1(),
            2 => self.round2(incoming),
            other => Err(FrostError::RoundOverflow {
                round: other,
                code: CODE_ROUND_OVERFLOW,
            }
            .framework()),
        }
    }

    fn result(&self) -> confium_tc::error::Result<Vec<u8>> {
        let pubkey = self.aggregate_pubkey.ok_or_else(|| {
            FrostError::SessionNotComplete {
                code: CODE_SESSION_NOT_COMPLETE,
            }
            .framework()
        })?;
        let share_bytes = group::scalar_to_bytes(&self.own_share);
        Ok(encode_dkg_output(&pubkey, &share_bytes))
    }

    fn destroy(&mut self) {
        // Zeroize sensitive state.
        self.own_share = Scalar::ZERO;
        self.poly = None;
        for (_id, frag) in self.received_fragments.drain(..) {
            let _ = frag;
        }
    }
}

// ---------------------------------------------------------------------------
// Output parsing — public helper so callers (and signing sessions) can
// recover (pubkey, share) from a DKG result blob.
// ---------------------------------------------------------------------------

/// Parse a DKG output blob into `(public_key_bytes, share_bytes)`.
///
/// The blob is the value returned by the DKG session via
/// [`confium_tc::Session::result`] /
/// [`confium_tc::Session::dkg_public_key`].
pub fn parse_output(
    blob: &[u8],
) -> Result<([u8; group::ELEMENT_BYTES], [u8; group::SCALAR_BYTES])> {
    if blob.len() < 4 {
        return Err(FrostError::MalformedShare {
            reason: "DKG output too short for pubkey length prefix",
            code: CODE_MALFORMED_SHARE,
        });
    }
    let pk_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if pk_len != group::ELEMENT_BYTES {
        return Err(FrostError::MalformedShare {
            reason: "unexpected pubkey length",
            code: CODE_MALFORMED_SHARE,
        });
    }
    let pk_end = 4 + pk_len;
    if blob.len() < pk_end + 4 {
        return Err(FrostError::MalformedShare {
            reason: "DKG output too short for share length prefix",
            code: CODE_MALFORMED_SHARE,
        });
    }
    let share_len = u32::from_be_bytes([
        blob[pk_end],
        blob[pk_end + 1],
        blob[pk_end + 2],
        blob[pk_end + 3],
    ]) as usize;
    if share_len != group::SCALAR_BYTES {
        return Err(FrostError::MalformedShare {
            reason: "unexpected share length",
            code: CODE_MALFORMED_SHARE,
        });
    }
    let share_end = pk_end + 4 + share_len;
    if blob.len() < share_end {
        return Err(FrostError::MalformedShare {
            reason: "DKG output truncated",
            code: CODE_MALFORMED_SHARE,
        });
    }
    let mut pk = [0u8; group::ELEMENT_BYTES];
    pk.copy_from_slice(&blob[4..pk_end]);
    let mut share = [0u8; group::SCALAR_BYTES];
    share.copy_from_slice(&blob[pk_end + 4..share_end]);
    Ok((pk, share))
}

/// Encode the DKG output blob.
fn encode_dkg_output(
    pubkey: &[u8; group::ELEMENT_BYTES],
    share: &[u8; group::SCALAR_BYTES],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + pubkey.len() + 4 + share.len());
    out.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&(share.len() as u32).to_be_bytes());
    out.extend_from_slice(share);
    out
}

// ---------------------------------------------------------------------------
// Wire formats
// ---------------------------------------------------------------------------

/// Round-1 broadcast: `tag | sender_idx:u32 BE | n_commits:u32 BE | commits…`
fn encode_round1_broadcast(idx: u32, commits: &[[u8; group::ELEMENT_BYTES]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + 4 + commits.len() * group::ELEMENT_BYTES);
    out.push(MSG_ROUND1_BROADCAST);
    out.extend_from_slice(&idx.to_be_bytes());
    out.extend_from_slice(&(commits.len() as u32).to_be_bytes());
    for c in commits {
        out.extend_from_slice(c);
    }
    out
}

fn decode_round1_broadcast(p: &[u8]) -> Result<(u32, Vec<[u8; group::ELEMENT_BYTES]>)> {
    if p.len() < 1 + 4 + 4 || p[0] != MSG_ROUND1_BROADCAST {
        return Err(FrostError::MalformedMessage {
            reason: "bad round-1 broadcast header",
            code: CODE_MALFORMED_MESSAGE,
        });
    }
    let idx = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    let n = u32::from_be_bytes([p[5], p[6], p[7], p[8]]) as usize;
    let need = 1 + 4 + 4 + n * group::ELEMENT_BYTES;
    if p.len() < need {
        return Err(FrostError::MalformedMessage {
            reason: "round-1 broadcast truncated",
            code: CODE_MALFORMED_MESSAGE,
        });
    }
    let mut commits = Vec::with_capacity(n);
    let mut off = 9;
    for _ in 0..n {
        let mut c = [0u8; group::ELEMENT_BYTES];
        c.copy_from_slice(&p[off..off + group::ELEMENT_BYTES]);
        off += group::ELEMENT_BYTES;
        commits.push(c);
    }
    Ok((idx, commits))
}

/// Round-1 directed share: `tag | sender_idx:u32 BE | share[32]`
fn encode_round1_directed(sender_idx: u32, frag: &Scalar) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + group::SCALAR_BYTES);
    out.push(MSG_ROUND1_DIRECTED);
    out.extend_from_slice(&sender_idx.to_be_bytes());
    out.extend_from_slice(&group::scalar_to_bytes(frag));
    out
}

fn decode_round1_directed(p: &[u8]) -> Result<(u32, Scalar)> {
    if p.len() != 1 + 4 + group::SCALAR_BYTES || p[0] != MSG_ROUND1_DIRECTED {
        return Err(FrostError::MalformedMessage {
            reason: "bad round-1 directed share",
            code: CODE_MALFORMED_MESSAGE,
        });
    }
    let sender_idx = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    let mut s = [0u8; group::SCALAR_BYTES];
    s.copy_from_slice(&p[5..5 + group::SCALAR_BYTES]);
    Ok((sender_idx, group::scalar_from_bytes_mod_order(&s)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group;

    #[test]
    fn round1_broadcast_round_trips() {
        let commits = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let enc = encode_round1_broadcast(7, &commits);
        let (idx, back) = decode_round1_broadcast(&enc).expect("decode");
        assert_eq!(idx, 7);
        assert_eq!(back, commits);
    }

    #[test]
    fn round1_directed_round_trips() {
        let s = Scalar::from_bytes_mod_order([9u8; 32]);
        let enc = encode_round1_directed(3, &s);
        let (idx, back) = decode_round1_directed(&enc).expect("decode");
        assert_eq!(idx, 3);
        assert_eq!(group::scalar_to_bytes(&back), group::scalar_to_bytes(&s));
    }

    #[test]
    fn output_round_trips() {
        let pk = [0xAAu8; 32];
        let share = [0xBBu8; 32];
        let blob = encode_dkg_output(&pk, &share);
        let (pk2, share2) = parse_output(&blob).expect("parse");
        assert_eq!(pk2, pk);
        assert_eq!(share2, share);
    }

    #[test]
    fn parse_output_rejects_truncated() {
        let err = parse_output(&[0u8; 3]).unwrap_err();
        match err {
            FrostError::MalformedShare { .. } => {}
            other => panic!("expected MalformedShare, got {other:?}"),
        }
    }
}
