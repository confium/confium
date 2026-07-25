//! Integration tests driving the in-repo `mock-tc-sig` scheme through
//! the [`VectorRunner`] using the sample vector TOML files shipped
//! under `crates/confium-test-harness/vectors/`.
//!
//! These tests link `confium-tc`, which registers `mock-tc-sig` at
//! link time via `inventory::submit!`. The runner resolves the scheme
//! through the same registry path real plugins use, so a pass here
//! exercises the full harness wiring: TOML parse → env + transport →
//! registry resolution → round driving → result comparison.

use std::path::PathBuf;

use confium_test_harness::{Outcome, TestVector, VectorRunner};

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

#[test]
fn mock_3_of_5_parses_and_runs_to_completion() {
    let path = vector_dir().join("mock-3-of-5.toml");
    let vector = TestVector::from_path(&path).expect("mock-3-of-5.toml must parse");
    assert_eq!(vector.scheme.name, "mock-tc-sig");
    assert_eq!(vector.test.parties, 5);
    assert_eq!(vector.test.threshold, 3);
    assert_eq!(
        vector.conformance_level,
        confium_test_harness::vector::ConformanceLevel::MustPass
    );
    assert_eq!(vector.expected_round_count, Some(3));
    assert!(vector.reference.as_deref().unwrap().starts_with("https://"));

    let result = VectorRunner::run(&vector).expect("run must not surface a harness error");
    assert_eq!(
        result.outcome,
        Outcome::Pass,
        "mock-tc-sig must complete the 3-of-5 vector; note: {:?}",
        result.note
    );
    assert_eq!(result.rounds, 3, "mock-tc-sig is a 3-round protocol");
    assert!(!result.output.is_empty(), "a signature must be produced");
}

#[test]
fn mock_2_of_3_runs_to_completion() {
    let path = vector_dir().join("mock-2-of-3.toml");
    let vector = TestVector::from_path(&path).expect("mock-2-of-3.toml must parse");
    assert_eq!(vector.test.parties, 3);
    assert_eq!(vector.test.threshold, 2);
    let result = VectorRunner::run(&vector).expect("run must not surface a harness error");
    assert_eq!(result.outcome, Outcome::Pass);
    assert_eq!(result.rounds, 3);
}

#[test]
fn mock_byzantine_drop_aborts_cleanly() {
    let path = vector_dir().join("mock-byzantine-drop.toml");
    let vector = TestVector::from_path(&path).expect("mock-byzantine-drop.toml must parse");
    assert_eq!(
        vector.test.threshold, 3,
        "vector requires full-coalition threshold"
    );
    assert_eq!(vector.peer_behavior.len(), 3);
    // The runner must NOT return Err — a scheme abort is a clean
    // Outcome::Aborted, not a harness fault.
    let result =
        VectorRunner::run(&vector).expect("byzantine abort must surface as a result, not an error");
    assert_eq!(
        result.outcome,
        Outcome::Aborted,
        "dropping a round-2 tag below threshold must abort; note: {:?}",
        result.note
    );
    assert!(
        result.output.is_empty(),
        "no signature must be produced on abort"
    );
    assert!(
        result
            .note
            .as_deref()
            .is_some_and(|n| n.contains("aborted")),
        "abort note must explain the abort: {:?}",
        result.note
    );
}
