//! Integration tests for the consolidated confium-tc crate.
//!
//! Verifies that all four areas (session primitives, coordinator, reshare,
//! kem) work together via the public API.

use chrono::Utc;
use confium_tc::coordinator::{
    Commitment, Coordinator, Share,
    session::{SessionRequest, SessionState, SignerId},
};
use confium_tc::reshare::{RefreshContribution, lagrange};

fn sample_session_request() -> SessionRequest {
    SessionRequest {
        quorum_id: "test-quorum".into(),
        scheme: "FROST-ed25519".into(),
        message: vec![0u8; 32],
        threshold: 2,
        num_parties: 3,
        unlock_window_minutes: 240,
        requested_by: "test-app".into(),
    }
}

#[test]
fn coordinator_full_session_lifecycle() {
    let mut coord = Coordinator::new();
    let id = coord.create_session(sample_session_request()).unwrap();
    assert_eq!(coord.session_state(&id), Some(SessionState::Pending));

    let alice: SignerId = "alice".into();
    let bob: SignerId = "bob".into();

    coord
        .submit_commitment(&id, sample_commitment(&alice))
        .unwrap();
    coord
        .submit_commitment(&id, sample_commitment(&bob))
        .unwrap();
    assert_eq!(
        coord.session_state(&id),
        Some(SessionState::CommitmentsCollected)
    );

    coord.submit_share(&id, sample_share(&alice)).unwrap();
    coord.submit_share(&id, sample_share(&bob)).unwrap();

    let sig = coord.aggregate(&id).unwrap();
    assert!(!sig.bytes.is_empty());
    assert_eq!(coord.session_state(&id), Some(SessionState::Completed));
}

#[test]
fn coordinator_audit_records_lifecycle() {
    let mut coord = Coordinator::new();
    let id = coord.create_session(sample_session_request()).unwrap();
    coord
        .submit_commitment(&id, sample_commitment(&"alice".into()))
        .unwrap();
    coord
        .submit_commitment(&id, sample_commitment(&"bob".into()))
        .unwrap();
    coord
        .submit_share(&id, sample_share(&"alice".into()))
        .unwrap();
    coord
        .submit_share(&id, sample_share(&"bob".into()))
        .unwrap();
    coord.aggregate(&id).unwrap();

    let entries = coord.audit_log().entries_for(&id);
    assert!(entries.len() >= 5);
}

#[test]
fn reshare_lagrange_interpolates_correctly() {
    // Integer arithmetic helpers for testing
    let points = vec![
        (
            1u64,
            lagrange::FieldElement::new(5i128.to_be_bytes().to_vec()),
        ),
        (
            2u64,
            lagrange::FieldElement::new(7i128.to_be_bytes().to_vec()),
        ),
    ];
    let result =
        lagrange::interpolate_at(&points, 0, &|x| x, &|a, b| a * b, &|a, b| a + b, &|a, b| {
            if b == 0 { i128::MAX } else { a / b }
        });
    let recovered = i128::from_be_bytes(result.0[..16].try_into().unwrap());
    assert_eq!(recovered, 3); // y = 2x + 3, at x=0 y=3
}

#[test]
fn reshare_refresh_contribution_round_trips() {
    let contributions = vec![
        RefreshContribution {
            from_party: 0,
            to_party: 1,
            bytes: vec![0x80; 32],
        },
        RefreshContribution {
            from_party: 1,
            to_party: 1,
            bytes: vec![0x80; 32],
        },
    ];
    let balanced = confium_tc::reshare::verify_refresh_preserves_aggregate(&contributions);
    assert!(balanced);
}

#[test]
fn kem_session_states_are_distinct() {
    use confium_tc::kem::session::KemSessionState;
    let states = [
        KemSessionState::Pending,
        KemSessionState::Round1Complete,
        KemSessionState::Completed,
        KemSessionState::Expired,
        KemSessionState::Aborted,
    ];
    for i in 0..states.len() {
        for j in (i + 1)..states.len() {
            assert_ne!(states[i], states[j], "states must be distinct");
        }
    }
}

fn sample_commitment(signer: &SignerId) -> Commitment {
    Commitment {
        signer_id: signer.clone(),
        bytes: vec![1u8; 32],
        signer_signature: vec![0u8; 64],
        submitted_at: Utc::now(),
    }
}

fn sample_share(signer: &SignerId) -> Share {
    Share {
        signer_id: signer.clone(),
        bytes: vec![2u8; 64],
        signer_signature: vec![0u8; 64],
        submitted_at: Utc::now(),
    }
}
