//! End-to-end integration test for the `mock-tc-sig` scheme.
//!
//! Spins up multiple parties in-process, drives each through the 3-round
//! protocol by routing round outputs between sessions, and asserts:
//!
//! 1. A full 3-of-3 coalition produces identical signatures on every party.
//! 2. A 2-of-3 coalition (threshold = 2) produces the *same* signature
//!    bytes as the 3-of-3 run — proving the threshold property.
//! 3. A 1-party run with threshold = 2 aborts in round 2 (below threshold).
//!
//! No network is involved — the test harness shuffles `Message`s between
//! `Session` handles directly, which is exactly what the transport layer
//! will do in production.

use confium_tc::Session;
use confium_tc::SessionParams;
use confium_tc::party::{Party, PartyList};
use confium_tc::share::Share;

/// The canonical scheme name for the mock.
const SCHEME: &str = "mock-tc-sig";

/// A fixed shared secret encoded as share bytes — identical on every
/// party, as a real threshold deployment would arrange out-of-band.
const SHARED_KEY: &[u8] = b"confium-mock-tc-sig-shared-key";

/// Build session params for one party.
fn make_params(parties: &[&str], this_idx: usize, threshold: u32, msg: &[u8]) -> SessionParams {
    let roster = parties
        .iter()
        .map(|id| Party::inproc(*id))
        .collect::<Vec<_>>();
    SessionParams {
        scheme: SCHEME.to_string(),
        parties: PartyList::from_parties(roster),
        threshold,
        this_party_idx: this_idx,
        local_share: Some(Share::new(SCHEME, SHARED_KEY.to_vec())),
        message: Some(msg.to_vec()),
    }
}

/// Run a full 3-round protocol for `participating` parties (a subset of
/// `roster`). Each party only sees messages addressed to it (broadcasts
/// from other participating parties). Returns the result bytes each
/// party computed, or an error captured at the round level.
enum Outcome {
    Ok(Vec<Vec<u8>>),
    Aborted(String),
}

fn run_session(roster: &[&str], participating: Vec<usize>, threshold: u32, msg: &[u8]) -> Outcome {
    let party_ids: Vec<String> = roster.iter().map(|s| s.to_string()).collect();
    let mut sessions: Vec<Session> = participating
        .iter()
        .map(|&idx| {
            Session::create(&make_params(roster, idx, threshold, msg)).expect("session created")
        })
        .collect();

    // Track each session's outgoing messages so we can route them next round.
    // Round 0: no incoming.
    let mut prev_outgoing: Vec<Vec<confium_tc::Message>> = Vec::new();
    for sess in sessions.iter_mut() {
        match sess.round_step(&[]) {
            Ok(r) => prev_outgoing.push(r.outgoing),
            Err(e) => return Outcome::Aborted(format!("round 0: {e}")),
        }
    }

    // Rounds 1 and 2: route every other party's previous-round broadcasts
    // into this party's incoming slice.
    for round_num in 1..=2 {
        let mut next_outgoing: Vec<Vec<confium_tc::Message>> = Vec::new();
        for (i, sess) in sessions.iter_mut().enumerate() {
            let mut incoming = Vec::new();
            for (j, outs) in prev_outgoing.iter().enumerate() {
                if i == j {
                    continue;
                }
                for m in outs {
                    // The mock uses broadcasts; deliver any message that is
                    // for this party (broadcast or directed).
                    if m.is_for(&party_ids[participating[i]]) {
                        incoming.push(m.clone());
                    }
                }
            }
            match sess.round_step(&incoming) {
                Ok(r) => next_outgoing.push(r.outgoing),
                Err(e) => return Outcome::Aborted(format!("round {round_num}: {e}")),
            }
        }
        // Check completion after round 2.
        if round_num == 2 {
            let results: Vec<Vec<u8>> = sessions
                .iter()
                .map(|s| s.result().expect("result after completion"))
                .collect();
            return Outcome::Ok(results);
        }
        prev_outgoing = next_outgoing;
    }
    unreachable!("loop returns in round 2 branch");
}

#[test]
fn three_of_three_produces_identical_signatures() {
    let roster = ["alice", "bob", "carol"];
    let msg = b"the quick brown fox";
    let outcome = run_session(&roster, vec![0, 1, 2], 2, msg);
    let sigs = match outcome {
        Outcome::Ok(s) => s,
        Outcome::Aborted(e) => panic!("3-of-3 should succeed: {e}"),
    };
    assert_eq!(sigs.len(), 3, "three participating parties");
    assert!(!sigs[0].is_empty(), "signature must be non-empty");
    assert_eq!(sigs[0], sigs[1], "alice == bob");
    assert_eq!(sigs[1], sigs[2], "bob == carol");
}

#[test]
fn two_of_three_matches_three_of_three() {
    let roster = ["alice", "bob", "carol"];
    let msg = b"threshold property check";

    // Full 3-of-3.
    let full = match run_session(&roster, vec![0, 1, 2], 2, msg) {
        Outcome::Ok(s) => s[0].clone(),
        Outcome::Aborted(e) => panic!("3-of-3 baseline failed: {e}"),
    };

    // Every 2-of-3 subset.
    for subset in [vec![0, 1], vec![0, 2], vec![1, 2]] {
        let partial = match run_session(&roster, subset.clone(), 2, msg) {
            Outcome::Ok(s) => s,
            Outcome::Aborted(e) => panic!("2-of-3 {:?} failed: {e}", subset),
        };
        assert_eq!(partial.len(), 2, "two participating parties");
        assert_eq!(partial[0], partial[1], "both parties agree in {:?}", subset);
        assert_eq!(
            partial[0], full,
            "2-of-3 {:?} must match 3-of-3 signature (threshold property)",
            subset
        );
    }
}

#[test]
fn one_party_below_threshold_aborts() {
    let roster = ["alice", "bob", "carol"];
    let msg = b"below threshold";
    // Threshold = 2 but only alice participates: the session should
    // abort in round 2 because fewer than T parties contributed.
    let outcome = run_session(&roster, vec![0], 2, msg);
    match outcome {
        Outcome::Aborted(reason) => {
            assert!(
                reason.contains("round 2"),
                "expected abort in round 2, got: {reason}"
            );
        }
        Outcome::Ok(_) => panic!("below-threshold 1-party run must abort, not complete"),
    }
}
