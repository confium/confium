//! CMP20 non-interactive distributed key generation over P-256.
//!
//! CMP20's headline DKG improvement over GG18 is that key generation is
//! **non-interactive**: a single broadcast round suffices. Each party
//! deals a Feldman VSS and bundles, into one outgoing message, both its
//! commitment list (broadcast) and every peer's polynomial evaluation
//! (directed). Recipients verify everything locally in the same round
//! and assemble their combined share + the joint public key without any
//! further interaction.
//!
//! After the round every party holds a combined share
//! `x_i = sum_d f_d(i)` and the joint public key
//! `X = prod_d g^{secret_d} = g^{sum secret_d}`. The combined secret is
//! never reconstructed.
//!
//! ## Rounds
//!
//! - **Round 1 — deal and assemble.** Broadcast Feldman commitments plus
//!   a directed share for every peer, all tagged for round 1. On
//!   receipt, verify each dealer's commitments against the bundled
//!   evaluation addressed to us, sum the verified shares into `x_i`,
//!   and compute the joint public key. Complete.

use elliptic_curve::PrimeField;
use elliptic_curve::rand_core::UnwrapErr;
use getrandom::SysRng;
use p256::{AffinePoint, ProjectivePoint, Scalar};

use confium_tc::Result;
use confium_tc::message::Message;
use confium_tc::registry::{RoundResult, SessionImpl};
use confium_tc::session::SessionParams;

use crate::error::{Cmp20ErrorCode, scheme_error};
use crate::share::{Cmp20Share, SHARE_BYTES};
use crate::vss::FeldmanVss;

/// CMP20 DKG scheme over P-256. Registered as `CMP20-ECDSA-P256`.
pub struct Cmp20DkgP256;

impl Cmp20DkgP256 {
    pub fn build_session(params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
        let party_id = params.parties.get(params.this_party_idx)?.id.clone();
        let n = params.parties.len();
        let t = params.threshold as usize;
        let party_idx_1based = (params.this_party_idx + 1) as u32;
        let party_ids: Vec<String> = params
            .parties
            .parties()
            .iter()
            .map(|p| p.id.clone())
            .collect();

        let vss = FeldmanVss::deal(&mut UnwrapErr(SysRng), n, t);

        Ok(Box::new(Cmp20DkgSession {
            party_id,
            party_idx_1based,
            party_ids,
            n,
            t,
            our_vss: vss,
            received_shares: Vec::new(),
            joint_public_key: None,
            our_combined_share: None,
            round_done: 0,
        }))
    }
}

pub struct Cmp20DkgSession {
    party_id: String,
    party_idx_1based: u32,
    party_ids: Vec<String>,
    n: usize,
    t: usize,
    our_vss: FeldmanVss,
    received_shares: Vec<(u64, Scalar)>,
    joint_public_key: Option<AffinePoint>,
    our_combined_share: Option<Scalar>,
    round_done: u8,
}

const TAG_COMMITMENTS: u8 = 0xCC;
const TAG_SHARE: u8 = 0xCE;

impl Cmp20DkgSession {
    /// Single non-interactive round: broadcast commitments and direct-send
    /// every peer its evaluation in one batch. All messages are tagged
    /// for round 1 — the framework delivers them all back in the same
    /// `round` call, where verification and assembly happen.
    fn round1_deal_and_assemble(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        let mut outgoing = Vec::with_capacity(1 + self.n);

        // Broadcast our commitment list.
        let commitments_bytes = FeldmanVss::encode_commitments(&self.our_vss.commitments);
        let mut bc_payload = Vec::with_capacity(3 + commitments_bytes.len());
        bc_payload.push(TAG_COMMITMENTS);
        bc_payload.push(self.party_idx_1based as u8);
        bc_payload.push(self.our_vss.commitments.len() as u8);
        bc_payload.extend_from_slice(&commitments_bytes);
        outgoing.push(Message::broadcast(&self.party_id, 1, bc_payload));

        // Directed-send each peer its polynomial evaluation in the same
        // round. CMP20's non-interactive property comes from bundling
        // these with the broadcast above.
        for (peer_pos, peer_id) in self.party_ids.iter().enumerate() {
            if peer_id == &self.party_id {
                continue;
            }
            let eval = self.our_vss.shares[peer_pos];
            let mut payload = Vec::with_capacity(2 + 32);
            payload.push(TAG_SHARE);
            payload.push(self.party_idx_1based as u8);
            payload.extend_from_slice(&eval.to_bytes());
            outgoing.push(Message::directed(&self.party_id, peer_id, 1, payload));
        }

        // Process incoming messages in the same round. On the first call
        // `incoming` is empty (no peer has broadcast yet) — we emit our
        // deal and stay incomplete so the framework re-enters with the
        // peer messages. When peer messages are present we verify and
        // assemble.
        if incoming.is_empty() {
            return Ok(RoundResult::new(outgoing, false));
        }

        let mut commitments_by_dealer: Vec<(u64, Vec<AffinePoint>)> = Vec::new();
        let mut own_evaluations: Vec<(u64, Scalar)> = Vec::new();

        for msg in incoming {
            if msg.round != 1 || msg.payload.is_empty() {
                continue;
            }
            let tag = msg.payload[0];
            match tag {
                TAG_COMMITMENTS => {
                    if msg.payload.len() < 3 {
                        return Err(scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE));
                    }
                    let dealer_idx = msg.payload[1] as u64;
                    let num_c = msg.payload[2] as usize;
                    let expected = 3 + num_c * 33;
                    if msg.payload.len() != expected {
                        return Err(scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE));
                    }
                    let cs = FeldmanVss::decode_commitments(&msg.payload[3..expected])
                        .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE))?;
                    if cs.len() != num_c || cs.len() < self.t {
                        return Err(scheme_error(Cmp20ErrorCode::VSS_VERIFY_FAILED));
                    }
                    commitments_by_dealer.push((dealer_idx, cs));
                }
                TAG_SHARE => {
                    if msg.payload.len() != 2 + 32 {
                        return Err(scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE));
                    }
                    if !msg.is_for(&self.party_id) {
                        continue;
                    }
                    let dealer_idx = msg.payload[1] as u64;
                    let mut eval_bytes = [0u8; 32];
                    eval_bytes.copy_from_slice(&msg.payload[2..34]);
                    let fb: p256::FieldBytes = eval_bytes.into();
                    let eval: Scalar = Option::from(Scalar::from_repr(fb))
                        .ok_or_else(|| scheme_error(Cmp20ErrorCode::BAD_ROUND_MESSAGE))?;
                    own_evaluations.push((dealer_idx, eval));
                }
                _ => continue,
            }
        }

        // Fold in our own self-evaluation + self-commitments so the
        // verification loop below covers our own deal uniformly.
        own_evaluations.push((
            self.party_idx_1based as u64,
            self.our_vss.shares[self.party_idx_1based as usize - 1],
        ));
        let self_idx = self.party_idx_1based as u64;
        if !commitments_by_dealer.iter().any(|(d, _)| *d == self_idx) {
            commitments_by_dealer.push((self_idx, self.our_vss.commitments.clone()));
        }

        let mut verified_shares: Vec<(u64, Scalar)> = Vec::new();
        for (dealer_idx, eval) in &own_evaluations {
            let commitments = commitments_by_dealer
                .iter()
                .find(|(d, _)| d == dealer_idx)
                .map(|(_, c)| c.as_slice())
                .ok_or_else(|| scheme_error(Cmp20ErrorCode::VSS_VERIFY_FAILED))?;
            if !FeldmanVss::verify_share(commitments, self.party_idx_1based as u64, *eval) {
                return Err(scheme_error(Cmp20ErrorCode::VSS_VERIFY_FAILED));
            }
            verified_shares.push((*dealer_idx, *eval));
        }

        let distinct_dealers: std::collections::HashSet<u64> =
            verified_shares.iter().map(|(d, _)| *d).collect();
        if distinct_dealers.len() < self.t {
            return Err(scheme_error(Cmp20ErrorCode::BELOW_THRESHOLD));
        }

        let combined: Scalar = verified_shares
            .iter()
            .fold(Scalar::ZERO, |acc, &(_, ev)| acc + ev);
        self.received_shares = verified_shares;
        self.our_combined_share = Some(combined);

        // Joint public key X = product over all dealers of C_0^{(d)}.
        let mut joint = ProjectivePoint::IDENTITY;
        for (_, cs) in &commitments_by_dealer {
            joint += ProjectivePoint::from(cs[0]);
        }
        self.joint_public_key = Some(joint.to_affine());

        Ok(RoundResult::done())
    }
}

impl SessionImpl for Cmp20DkgSession {
    fn round(&mut self, incoming: &[Message]) -> Result<RoundResult> {
        self.round_done = self.round_done.checked_add(1).ok_or_else(|| {
            confium_tc::error::RoundOverflowSnafu {
                round: self.round_done,
            }
            .build()
        })?;
        match self.round_done {
            // CMP20 DKG is logically one round, but the framework drives
            // it as two `round` calls: the first emits our deal with no
            // incoming, the second receives peer deals and assembles.
            // Both calls dispatch to the same handler, which branches on
            // whether `incoming` is populated.
            1 | 2 => self.round1_deal_and_assemble(incoming),
            other => Err(confium_tc::error::RoundOverflowSnafu { round: other }.build()),
        }
    }

    fn result(&self) -> Result<Vec<u8>> {
        if self.round_done < 1 || self.our_combined_share.is_none() {
            return Err(confium_tc::error::SessionNotCompleteSnafu {}.build());
        }
        let combined = self
            .our_combined_share
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        let pk = self
            .joint_public_key
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        let x_i: p256::NonZeroScalar = Option::from(p256::NonZeroScalar::new(combined))
            .ok_or_else(|| scheme_error(Cmp20ErrorCode::INTERNAL))?;
        let share = Cmp20Share::from_parts(x_i, pk, self.party_idx_1based);
        Ok(share.to_bytes())
    }

    fn destroy(&mut self) {
        if let Some(s) = self.our_combined_share.take() {
            let _ = s;
        }
        for (_, s) in self.received_shares.drain(..) {
            let _ = s;
        }
        self.our_vss.shares.fill(Scalar::ZERO);
    }
}

/// Parse a DKG-produced share blob.
pub fn parse_share(bytes: &[u8]) -> Result<Cmp20Share> {
    if bytes.len() != SHARE_BYTES {
        return Err(scheme_error(Cmp20ErrorCode::BAD_SHARE));
    }
    Cmp20Share::from_bytes(bytes)
}

#[cfg(test)]
pub(crate) fn reconstruct_secret_for_test(shares: &[Cmp20Share]) -> Scalar {
    use crate::lagrange;
    let pairs: Vec<(Scalar, Scalar)> = shares
        .iter()
        .map(|s| (Scalar::from(s.party_idx), s.scalar()))
        .collect();
    lagrange::lagrange_weighted_sum(&pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use confium_tc::party::{Party, PartyList};
    use confium_tc::share::Share;
    use elliptic_curve::sec1::ToSec1Point;

    fn params(n: usize, t: u32, idx: usize) -> SessionParams {
        let roster: Vec<Party> = (0..n).map(|i| Party::inproc(format!("p{}", i))).collect();
        SessionParams {
            scheme: crate::DKG_SCHEME_NAME.to_string(),
            parties: PartyList::from_parties(roster),
            threshold: t,
            this_party_idx: idx,
            local_share: None,
            message: None,
        }
    }

    /// Drive the non-interactive DKG to completion. The first `round`
    /// call emits each party's deal; the second receives peer deals and
    /// assembles. From the protocol's perspective this is still a single
    /// broadcast round — the two calls reflect the framework's
    /// send-then-receive cadence, not an extra protocol round.
    fn run_dkg(n: usize, t: u32) -> Vec<Cmp20Share> {
        let party_ids: Vec<String> = (0..n).map(|i| format!("p{}", i)).collect();
        let mut sessions: Vec<Box<dyn SessionImpl>> = (0..n)
            .map(|i| {
                let p = params(n, t, i);
                Cmp20DkgP256::build_session(&p).expect("session")
            })
            .collect();

        // First pass: every party emits its deal (no incoming yet).
        let mut outgoing_r1: Vec<Vec<Message>> = Vec::new();
        for sess in sessions.iter_mut() {
            let r = sess.round(&[]).expect("round 1 deal");
            assert!(!r.complete, "round 1 must not complete without peer input");
            outgoing_r1.push(r.outgoing);
        }

        // Route each peer's messages to its recipients.
        let mut incoming: Vec<Vec<Message>> = vec![Vec::new(); n];
        for (sender_pos, outs) in outgoing_r1.iter().enumerate() {
            for m in outs {
                for (recv_pos, pid) in party_ids.iter().enumerate() {
                    if recv_pos == sender_pos {
                        continue;
                    }
                    if m.is_for(pid) {
                        incoming[recv_pos].push(m.clone());
                    }
                }
            }
        }

        // Second pass: each party verifies and assembles. This is still
        // the same protocol round — no new messages are emitted.
        for (i, sess) in sessions.iter_mut().enumerate() {
            let r = sess.round(&incoming[i]).expect("round 1 assemble");
            assert!(
                r.complete,
                "DKG must complete after the single broadcast round"
            );
        }

        sessions
            .iter()
            .map(|s| {
                let bytes = s.result().expect("result");
                Cmp20Share::from_bytes(&bytes).expect("share decodes")
            })
            .collect()
    }

    #[test]
    fn dkg_two_of_three_produces_consistent_shares() {
        let shares = run_dkg(3, 2);
        assert_eq!(shares.len(), 3);
        let pk0 = shares[0].public_key;
        for s in &shares[1..] {
            let a = pk0.to_sec1_point(true);
            let b = s.public_key.to_sec1_point(true);
            assert_eq!(a.as_bytes(), b.as_bytes(), "joint public key must match");
        }
        let secret_01 = reconstruct_secret_for_test(&shares[0..2]);
        let secret_02 = reconstruct_secret_for_test(&[shares[0].clone(), shares[2].clone()]);
        let secret_12 = reconstruct_secret_for_test(&shares[1..3]);
        assert_eq!(secret_01, secret_02);
        assert_eq!(secret_02, secret_12);
        let g = ProjectivePoint::GENERATOR;
        let expected_pk = (g * secret_01).to_affine();
        let got_pk = shares[0].public_key.to_sec1_point(true);
        let want_pk = expected_pk.to_sec1_point(true);
        assert_eq!(got_pk.as_bytes(), want_pk.as_bytes());
    }

    #[test]
    fn dkg_three_of_three_produces_consistent_shares() {
        let shares = run_dkg(3, 3);
        let secret = reconstruct_secret_for_test(&shares);
        let g = ProjectivePoint::GENERATOR;
        let pk = (g * secret).to_affine().to_sec1_point(true);
        assert_eq!(
            pk.as_bytes(),
            shares[0].public_key.to_sec1_point(true).as_bytes()
        );
    }

    #[test]
    fn dkg_share_is_loadable_as_framework_share() {
        let shares = run_dkg(3, 2);
        let bytes = shares[0].to_bytes();
        let fw = Share::new(crate::DKG_SCHEME_NAME, bytes);
        assert_eq!(fw.scheme(), crate::DKG_SCHEME_NAME);
        let rt = Share::from_bytes(&fw.to_bytes()).expect("framework decode");
        assert_eq!(rt.scheme(), crate::DKG_SCHEME_NAME);
        let inner = Cmp20Share::from_bytes(rt.bytes()).expect("inner decode");
        assert_eq!(inner.party_idx, shares[0].party_idx);
    }
}
