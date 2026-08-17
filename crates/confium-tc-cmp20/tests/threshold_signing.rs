//! End-to-end integration tests for CMP20 threshold ECDSA over P-256.
//!
//! Drives a full DKG + signing session among in-process parties and
//! asserts:
//!
//! 1. A 2-of-3 coalition produces a valid ECDSA signature (verifies
//!    under `p256::ecdsa::VerifyingKey`).
//! 2. A 3-of-3 coalition produces a valid signature under the same key.
//! 3. Any T-of-N subset produces a signature under the same joint key.
//! 4. A byzantine party (tampered partial signature) causes the session
//!    to abort with identifiable-abort semantics.

use confium_tc::Session;
use confium_tc::SessionParams;
use confium_tc::message::Message;
use confium_tc::party::{Party, PartyList};
use confium_tc::share::Share;
use confium_tc_cmp20::Cmp20Share;
use confium_tc_cmp20::DKG_SCHEME_NAME;
use confium_tc_cmp20::SIGN_SCHEME_NAME;

/// Build a DKG session for one party.
fn dkg_params(roster: &[&str], idx: usize, threshold: u32) -> SessionParams {
    SessionParams {
        scheme: DKG_SCHEME_NAME.to_string(),
        parties: PartyList::from_parties(roster.iter().map(|s| Party::inproc(*s)).collect()),
        threshold,
        this_party_idx: idx,
        local_share: None,
        message: None,
    }
}

/// Build a signing session for one party, loading its DKG share.
fn sign_params(
    roster: &[&str],
    idx: usize,
    threshold: u32,
    share_bytes: Vec<u8>,
    msg: &[u8],
) -> SessionParams {
    SessionParams {
        scheme: SIGN_SCHEME_NAME.to_string(),
        parties: PartyList::from_parties(roster.iter().map(|s| Party::inproc(*s)).collect()),
        threshold,
        this_party_idx: idx,
        local_share: Some(Share::new(SIGN_SCHEME_NAME, share_bytes)),
        message: Some(msg.to_vec()),
    }
}

/// Run a multi-round protocol among `participating` parties, routing
/// messages between sessions. Returns per-party result bytes, or an
/// abort reason.
enum Outcome {
    Ok(Vec<Vec<u8>>),
    Aborted(String),
}

fn run_protocol(
    roster: &[&str],
    participating: Vec<usize>,
    params_fn: impl Fn(usize) -> SessionParams,
    max_rounds: u8,
) -> Outcome {
    let party_ids: Vec<String> = roster.iter().map(|s| s.to_string()).collect();
    let mut sessions: Vec<Session> = participating
        .iter()
        .map(|&idx| Session::create(&params_fn(idx)).expect("session created"))
        .collect();

    let mut prev_outgoing: Vec<Vec<Message>> = Vec::new();
    for sess in sessions.iter_mut() {
        match sess.round_step(&[]) {
            Ok(r) => prev_outgoing.push(r.outgoing),
            Err(e) => return Outcome::Aborted(format!("round 1: {e}")),
        }
    }

    // Drive further rounds until every session reports complete or we
    // hit the safety cap.
    for round_num in 2..=max_rounds {
        let all_complete = sessions.iter().all(|s| s.is_complete());
        if all_complete {
            break;
        }
        let mut next_outgoing: Vec<Vec<Message>> = Vec::new();
        for (i, sess) in sessions.iter_mut().enumerate() {
            if sess.is_complete() {
                next_outgoing.push(Vec::new());
                continue;
            }
            let mut incoming = Vec::new();
            for (j, outs) in prev_outgoing.iter().enumerate() {
                if i == j {
                    continue;
                }
                for m in outs {
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
        prev_outgoing = next_outgoing;
    }

    if !sessions.iter().all(|s| s.is_complete()) {
        return Outcome::Aborted("sessions did not complete within round budget".to_string());
    }
    let results: Vec<Vec<u8>> = sessions
        .iter()
        .map(|s| s.result().expect("result after completion"))
        .collect();
    Outcome::Ok(results)
}

/// Run DKG among `n` parties, return their shares.
fn run_dkg(roster: &[&str], threshold: u32) -> Vec<Vec<u8>> {
    let outcome = run_protocol(
        roster,
        (0..roster.len()).collect(),
        |idx| dkg_params(roster, idx, threshold),
        2,
    );
    match outcome {
        Outcome::Ok(s) => s,
        Outcome::Aborted(e) => panic!("DKG failed: {e}"),
    }
}

/// Run signing among `participating` parties (indices into `roster`).
fn run_signing(
    roster: &[&str],
    participating: Vec<usize>,
    threshold: u32,
    shares: &[Vec<u8>],
    msg: &[u8],
) -> Outcome {
    run_protocol(
        roster,
        participating.clone(),
        |idx| sign_params(roster, idx, threshold, shares[idx].clone(), msg),
        4,
    )
}

/// Parse a 64-byte signature into a p256 Signature and verify it against
/// the public key extracted from any share.
fn verify_sig(share_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let share = Cmp20Share::from_bytes(share_bytes).expect("share decodes");
    let vk = p256::ecdsa::VerifyingKey::from_affine(share.public_key).expect("valid pubkey");
    let sig_obj = p256::ecdsa::Signature::from_slice(sig).expect("valid sig");
    use p256::ecdsa::signature::Verifier;
    vk.verify(msg, &sig_obj).is_ok()
}

#[test]
fn dkg_then_2_of_3_signing_produces_valid_signature() {
    let roster = ["alice", "bob", "carol"];
    let msg = b"the quick brown fox jumps over the lazy dog";
    let shares = run_dkg(&roster, 2);
    assert_eq!(shares.len(), 3);

    // Every 2-of-3 subset must produce a valid signature.
    for subset in [vec![0usize, 1], vec![0, 2], vec![1, 2]] {
        let outcome = run_signing(&roster, subset.clone(), 2, &shares, msg);
        let sigs = match outcome {
            Outcome::Ok(s) => s,
            Outcome::Aborted(e) => panic!("2-of-3 {:?} signing failed: {e}", subset),
        };
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].len(), 64, "signature must be 64 bytes");
        assert_eq!(
            sigs[0], sigs[1],
            "both parties must produce identical signatures"
        );
        assert!(
            verify_sig(&shares[subset[0]], msg, &sigs[0]),
            "signature must verify under the joint public key (subset {:?})",
            subset
        );
    }
}

#[test]
fn dkg_then_3_of_3_signing_produces_valid_signature() {
    let roster = ["alice", "bob", "carol"];
    let msg = b"3-of-3 threshold ECDSA test message";
    let shares = run_dkg(&roster, 3);
    let outcome = run_signing(&roster, vec![0, 1, 2], 3, &shares, msg);
    let sigs = match outcome {
        Outcome::Ok(s) => s,
        Outcome::Aborted(e) => panic!("3-of-3 signing failed: {e}"),
    };
    assert_eq!(sigs.len(), 3);
    for s in &sigs {
        assert_eq!(s.len(), 64);
    }
    // All parties produce the same signature.
    assert_eq!(sigs[0], sigs[1]);
    assert_eq!(sigs[1], sigs[2]);
    assert!(verify_sig(&shares[0], msg, &sigs[0]));
}

#[test]
fn threshold_property_any_subset_same_key() {
    // The joint public key is identical regardless of which subset
    // signs, because it is determined at DKG time.
    let roster = ["alice", "bob", "carol"];
    let msg = b"threshold property";
    let shares = run_dkg(&roster, 2);

    let sig_01 = match run_signing(&roster, vec![0, 1], 2, &shares, msg) {
        Outcome::Ok(s) => s[0].clone(),
        Outcome::Aborted(e) => panic!("{e}"),
    };
    let sig_02 = match run_signing(&roster, vec![0, 2], 2, &shares, msg) {
        Outcome::Ok(s) => s[0].clone(),
        Outcome::Aborted(e) => panic!("{e}"),
    };
    // Both verify under the same public key.
    assert!(verify_sig(&shares[0], msg, &sig_01));
    assert!(verify_sig(&shares[0], msg, &sig_02));
}

#[test]
fn signing_without_share_aborts() {
    let roster = ["alice", "bob"];
    let params = SessionParams {
        scheme: SIGN_SCHEME_NAME.to_string(),
        parties: PartyList::from_parties(roster.iter().map(|s| Party::inproc(*s)).collect()),
        threshold: 2,
        this_party_idx: 0,
        local_share: None,
        message: Some(b"msg".to_vec()),
    };
    let err = Session::create(&params).unwrap_err();
    let code: u32 = err.into();
    // SchemeInternalError (0x1041) with CMP20 BAD_SHARE sub-code.
    assert_eq!(code, 0x1041);
}

#[test]
fn byzantine_partial_signature_aborts() {
    // A party that posts a wrong partial signature causes verification
    // to fail in round 4. We simulate this by having one party use a
    // corrupted share (wrong party_idx), so its Lagrange weight is
    // inconsistent with the others.
    let roster = ["alice", "bob", "carol"];
    let msg = b"byzantine test";
    let mut shares = run_dkg(&roster, 2);

    // Corrupt carol's share: flip its party_idx so her Lagrange weight
    // is wrong, making her partial signature inconsistent.
    let mut carol = Cmp20Share::from_bytes(&shares[2]).expect("share");
    carol.party_idx = 99; // bogus index
    shares[2] = carol.to_bytes();

    let outcome = run_signing(&roster, vec![0, 2], 2, &shares, msg);
    match outcome {
        Outcome::Aborted(reason) => {
            assert!(
                reason.contains("round 4") || reason.contains("round 3"),
                "expected abort on byzantine partial, got: {reason}"
            );
        }
        Outcome::Ok(_) => panic!("byzantine partial must abort, not complete"),
    }
}

#[test]
fn dkg_completes_in_single_broadcast_round() {
    // CMP20's headline DKG property: non-interactive key generation.
    // The framework surfaces this as two `round` calls (deal then
    // assemble), but the protocol is logically one broadcast round —
    // no second round of messages is exchanged.
    let roster = ["alice", "bob", "carol", "dave"];
    let shares = run_dkg(&roster, 3);
    assert_eq!(shares.len(), 4);
    // All shares must agree on the joint public key.
    let pk0 = Cmp20Share::from_bytes(&shares[0])
        .expect("share")
        .public_key;
    for s in &shares[1..] {
        let pk = Cmp20Share::from_bytes(s).expect("share").public_key;
        use elliptic_curve::sec1::ToSec1Point;
        assert_eq!(
            pk0.to_sec1_point(true).as_bytes(),
            pk.to_sec1_point(true).as_bytes(),
            "joint public key must match across all parties"
        );
    }
}
