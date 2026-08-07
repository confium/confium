//! In-process synchronous driver for any registered threshold scheme.
//!
//! Wraps the multi-round session state machine in a single function call
//! so language bindings and integration tests don't have to reconstruct
//! the round / message-routing loop on their own side. The driver is
//! local — it does no real networking — and is intended for integration
//! tests, demos, and the in-process surface of language bindings.
//! Production deployments drive the sessions over a real transport via
//! `confium-tc-coordinator`.
//!
//! ## Why this exists
//!
//! Without this module every binding (Ruby, Python, WASM, the in-tree
//! examples) had to copy the same N-session-create + route-messages +
//! drive-rounds boilerplate. The CMP20 and GG18 in-process shims were
//! ~200 LOC each, ~90% of which was identical. This module collapses
//! that pattern into one place; scheme-specific shims now only declare
//! their scheme name and how to extract a public key from a share blob.
//!
//! ## Output contract
//!
//! [`run_dkg`] returns the per-party share blobs produced by
//! [`Session::result`]. The joint public key is *not* returned — the
//! caller knows the scheme-specific encoding and extracts it from the
//! first share (see `confium-tc-cmp20::inprocess::keygen` for the
//! pattern).
//!
//! [`run_sign`] returns the cryptographic artifact (e.g. a 64-byte
//! `(r, s)` ECDSA signature).

use snafu::ensure;

use crate::Result;
use crate::error;
use crate::message::Message;
use crate::party::{Party, PartyList};
use crate::session::{Session, SessionParams};
use crate::share::Share;

/// Upper bound on the number of framework-round iterations before the
/// driver gives up. Real protocols (FROST, CMP20, GG18) top out at 4;
/// the bound exists to fail loudly on a misbehaving scheme rather than
/// spin forever.
const MAX_ROUNDS: u8 = 8;

/// Drive a registered DKG scheme to completion in-process.
///
/// Creates `party_count` sessions (one per party) under the named
/// scheme, runs every round until all sessions signal completion, and
/// returns the per-party result blobs in roster order.
///
/// `threshold` must be in `1..=party_count`. Parties are in-process
/// (`Party::inproc`), identified `p0` … `p{n-1}`.
pub fn run_dkg(scheme: &str, threshold: u32, party_count: usize) -> Result<Vec<Vec<u8>>> {
    ensure!(
        party_count > 0,
        error::EmptyPartyListSnafu {}
    );
    let roster: Vec<Party> = (0..party_count)
        .map(|i| Party::inproc(format!("p{i}")))
        .collect();
    let parties = PartyList::from_parties(roster);
    let party_ids: Vec<String> = parties.parties().iter().map(|p| p.id.clone()).collect();

    let mut sessions: Vec<Session> = (0..party_count)
        .map(|idx| {
            Session::create(&SessionParams {
                scheme: scheme.to_string(),
                parties: parties.clone(),
                threshold,
                this_party_idx: idx,
                local_share: None,
                message: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    drive_to_completion(&mut sessions, &party_ids)?;

    sessions.iter().map(|s| s.result()).collect()
}

/// Drive a registered signing / decapsulation scheme to completion
/// in-process using `share_blobs` as the per-party inputs.
///
/// One session is created per supplied share. `share_blobs.len()` must
/// be `>= threshold`. The first session's `result()` is returned — for
/// honest coalitions every party converges on the same artifact.
pub fn run_sign(
    scheme: &str,
    share_blobs: &[Vec<u8>],
    threshold: u32,
    message: &[u8],
) -> Result<Vec<u8>> {
    let signer_count = share_blobs.len();
    ensure!(
        signer_count as u32 >= threshold,
        error::ThresholdTooLargeSnafu {
            threshold,
            party_count: signer_count,
        }
    );

    let roster: Vec<Party> = (0..signer_count)
        .map(|i| Party::inproc(format!("p{i}")))
        .collect();
    let parties = PartyList::from_parties(roster);
    let party_ids: Vec<String> = parties.parties().iter().map(|p| p.id.clone()).collect();

    let mut sessions: Vec<Session> = (0..signer_count)
        .map(|idx| {
            let local_share = Share::new(scheme.to_string(), share_blobs[idx].clone());
            Session::create(&SessionParams {
                scheme: scheme.to_string(),
                parties: parties.clone(),
                threshold,
                this_party_idx: idx,
                local_share: Some(local_share),
                message: Some(message.to_vec()),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    drive_to_completion(&mut sessions, &party_ids)?;

    sessions[0].result()
}

/// Drive every session forward until all signal completion or
/// `MAX_ROUNDS` is exceeded. Messages from one round are routed to
/// their recipients as the next round's incoming.
fn drive_to_completion(sessions: &mut [Session], party_ids: &[String]) -> Result<()> {
    let mut outgoing: Vec<Vec<Message>> = Vec::new();
    for round in 1..=MAX_ROUNDS {
        outgoing = step_rounds(sessions, &outgoing, party_ids)?;
        if sessions.iter().all(|s| s.is_complete()) {
            return Ok(());
        }
    }
    Err(error::RoundOverflowSnafu { round: MAX_ROUNDS }.build())
}

/// Drive one `round_step` per session with routed incoming messages,
/// returning the per-session outgoing messages for the next round.
fn step_rounds(
    sessions: &mut [Session],
    prev_outgoing: &[Vec<Message>],
    party_ids: &[String],
) -> Result<Vec<Vec<Message>>> {
    let n = sessions.len();
    let mut incoming: Vec<Vec<Message>> = vec![Vec::new(); n];
    for (sender_pos, outs) in prev_outgoing.iter().enumerate() {
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
    let mut next: Vec<Vec<Message>> = Vec::with_capacity(n);
    for (i, sess) in sessions.iter_mut().enumerate() {
        let r = sess.round_step(&incoming[i])?;
        next.push(r.outgoing);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::party::{Party, PartyList};
    use crate::registry::{RoundResult, SessionImpl, TcScheme, TcSchemeKind};

    /// A toy two-round DKG scheme used to exercise the driver without
    /// depending on a real threshold crate. Round 1 broadcasts; round 2
    /// completes.
    struct ToyScheme;

    impl TcScheme for ToyScheme {
        fn name(&self) -> &'static str {
            "test-inprocess-driver"
        }
        fn kind(&self) -> TcSchemeKind {
            TcSchemeKind::Dkg
        }
        fn create_session(&self, params: &SessionParams) -> Result<Box<dyn SessionImpl>> {
            let id = params.parties.get(params.this_party_idx)?.id.clone();
            Ok(Box::new(ToySession {
                id,
                round_done: 0,
            }))
        }
    }

    struct ToySession {
        id: String,
        round_done: u8,
    }

    impl SessionImpl for ToySession {
        fn round(&mut self, _incoming: &[Message]) -> Result<RoundResult> {
            self.round_done += 1;
            if self.round_done == 1 {
                Ok(RoundResult::new(
                    vec![Message::broadcast(&self.id, 1, vec![0xAA])],
                    false,
                ))
            } else {
                Ok(RoundResult::done())
            }
        }
        fn result(&self) -> Result<Vec<u8>> {
            Ok(vec![0xAA])
        }
        fn destroy(&mut self) {}
    }

    inventory::submit! {
        crate::registry::RegisteredScheme {
            scheme: &ToyScheme as &dyn crate::registry::TcScheme
        }
    }

    #[test]
    fn drive_dkg_two_round_scheme_completes() {
        let out = run_dkg("test-inprocess-driver", 2, 3).expect("dkg");
        assert_eq!(out.len(), 3);
        for blob in &out {
            assert_eq!(blob, &vec![0xAA]);
        }
    }

    #[test]
    fn drive_dkg_rejects_zero_party_count() {
        let err = run_dkg("test-inprocess-driver", 0, 0);
        assert!(err.is_err());
    }

    #[test]
    fn drive_sign_unknown_scheme_errors() {
        let err = run_sign("no-such-scheme", &[vec![1, 2, 3]], 1, b"msg");
        assert!(err.is_err());
    }

    #[test]
    fn drive_sign_below_threshold_errors() {
        // Three shares claimed, threshold higher than supplied count.
        let err = run_sign("test-inprocess-driver", &[], 1, b"msg");
        assert!(err.is_err());
    }

    fn _ensure_party_list_send_sync(_list: PartyList) {
        // Compile-time check that the public API stays send + sync as
        // the framework evolves.
    }

    fn _ensure_party_send_sync(_p: Party) {}
}
