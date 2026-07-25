//! Outcome of running one test vector.
//!
//! A [`TestResult`] records whether the protocol completed, what bytes
//! it produced, how many rounds and bytes-on-the-wire it took, and how
//! long it ran for. The reporter ([`crate::report`]) turns a batch of
//! these into the JSON NIST consumes.

use std::time::Duration;

use crate::vector::TestVector;

/// Whether the run succeeded, aborted cleanly (e.g. detected Byzantine
/// misbehavior), or errored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Protocol completed and produced output matching (if specified)
    /// the vector's expected bytes.
    Pass,
    /// Protocol completed but the output didn't match the expected
    /// bytes (only possible when `expected_signature_hex` was set).
    Fail,
    /// Protocol completed but a non-conformance was observed that the
    /// vector's conformance level downgrades from an error to a warning
    /// (e.g. a `should_pass` vector whose output mismatched). Recorded
    /// in the report; does not gate the candidate.
    Warn,
    /// Protocol aborted cleanly — the scheme detected the configured
    /// Byzantine behavior and signaled misbehavior. Counts as a pass
    /// for Byzantine-detection vectors.
    Aborted,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Fail => "fail",
            Outcome::Warn => "warn",
            Outcome::Aborted => "aborted",
        }
    }
}

/// Result of executing one [`TestVector`] against one scheme.
#[derive(Debug, Clone)]
pub struct TestResult {
    pub scheme_name: String,
    pub scheme_version: String,
    pub parties: u32,
    pub threshold: u32,
    pub outcome: Outcome,
    /// Bytes the protocol produced (signature, DKG output, …). Empty
    /// for aborted runs.
    pub output: Vec<u8>,
    /// Total messages exchanged across all rounds, all parties.
    pub messages_exchanged: u64,
    /// Total bytes carried by those messages.
    pub bytes_exchanged: u64,
    /// Number of rounds the protocol ran before completing or aborting.
    pub rounds: u8,
    /// Wall time of the run, captured by the runner.
    pub elapsed: Duration,
    /// Human-readable note — e.g. mismatch detail, abort reason.
    pub note: Option<String>,
}

impl TestResult {
    /// Build a result from a vector + the runtime observations. The
    /// caller supplies the produced output and the observed round
    /// count; this constructor decides `Pass` / `Fail` / `Warn` by
    /// comparing against the vector's expected bytes and conformance
    /// level:
    ///
    /// - Output matches (or no expected bytes) and round count matches
    ///   (or no `expected_round_count` set) → `Pass`.
    /// - Output mismatches on a `must_pass` vector → `Fail`.
    /// - Output mismatches on a `should_pass` vector → `Warn`.
    /// - Output mismatches on an `informational` vector → `Pass` (the
    ///   mismatch is recorded in `note` but never gates the candidate).
    /// - Round count differs from `expected_round_count` → `Warn` even
    ///   on a `must_pass` vector (the implementation produced a valid
    ///   signature; it just took a different number of rounds). The
    ///   mismatch is appended to the note.
    pub fn from_run(
        vector: &TestVector,
        output: Vec<u8>,
        messages_exchanged: u64,
        bytes_exchanged: u64,
        rounds: u8,
        elapsed: Duration,
    ) -> Self {
        let output_matches = match vector.test.expected_bytes() {
            Some(expected) => expected == output,
            None => true,
        };
        let mismatch_note = if output_matches {
            None
        } else {
            Some(format!(
                "output mismatch: expected {} bytes, got {} bytes",
                vector.test.expected_bytes().map(|e| e.len()).unwrap_or(0),
                output.len()
            ))
        };

        let round_note = match vector.expected_round_count {
            Some(expected) if expected != rounds => Some(format!(
                "round count differs: expected {}, observed {}",
                expected, rounds
            )),
            _ => None,
        };

        use crate::vector::ConformanceLevel;
        let outcome = if output_matches {
            // Output is correct. A round-count divergence on an
            // otherwise-passing vector is still only a warning — the
            // signature was produced, the implementation just took a
            // different number of rounds than the vector expected.
            match round_note {
                Some(_) => Outcome::Warn,
                None => Outcome::Pass,
            }
        } else {
            match vector.conformance_level {
                ConformanceLevel::MustPass => Outcome::Fail,
                ConformanceLevel::ShouldPass => Outcome::Warn,
                // Informational failures never gate the candidate.
                ConformanceLevel::Informational => Outcome::Pass,
            }
        };

        let note = match (mismatch_note, round_note) {
            (Some(a), Some(b)) => Some(format!("{}; {}", a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        TestResult {
            scheme_name: vector.scheme.name.clone(),
            scheme_version: vector.scheme.version.clone(),
            parties: vector.test.parties,
            threshold: vector.test.threshold,
            outcome,
            output,
            messages_exchanged,
            bytes_exchanged,
            rounds,
            elapsed,
            note,
        }
    }

    /// Construct an aborted result (no output, scheme signaled
    /// misbehavior). Used by the runner when the configured Byzantine
    /// behavior tripped the scheme's abort path.
    pub fn aborted(
        vector: &TestVector,
        reason: impl Into<String>,
        rounds: u8,
        elapsed: Duration,
    ) -> Self {
        TestResult {
            scheme_name: vector.scheme.name.clone(),
            scheme_version: vector.scheme.version.clone(),
            parties: vector.test.parties,
            threshold: vector.test.threshold,
            outcome: Outcome::Aborted,
            output: Vec::new(),
            messages_exchanged: 0,
            bytes_exchanged: 0,
            rounds,
            elapsed,
            note: Some(reason.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::ConformanceLevel;
    use crate::vector::SchemeSpec;

    fn vector(expected: Option<&str>) -> TestVector {
        TestVector {
            scheme: SchemeSpec {
                name: "test".into(),
                version: "1".into(),
            },
            test: crate::vector::TestVectorTest {
                parties: 3,
                threshold: 2,
                message: String::new(),
                seed: String::new(),
                expected_signature_hex: expected.unwrap_or("").to_string(),
            },
            peer_behavior: Vec::new(),
            conformance_level: Default::default(),
            reference: None,
            expected_round_count: None,
            share_material: None,
        }
    }

    fn vector_with_level(level: ConformanceLevel, expected: Option<&str>) -> TestVector {
        let mut v = vector(expected);
        v.conformance_level = level;
        v
    }

    #[test]
    fn pass_when_no_expected_bytes() {
        let v = vector(None);
        let r = TestResult::from_run(&v, vec![1, 2, 3], 4, 12, 2, Duration::from_micros(50));
        assert_eq!(r.outcome, Outcome::Pass);
        assert!(r.note.is_none());
    }

    #[test]
    fn pass_when_output_matches_expected() {
        let v = vector(Some("0x010203"));
        let r = TestResult::from_run(&v, vec![1, 2, 3], 4, 12, 2, Duration::from_micros(50));
        assert_eq!(r.outcome, Outcome::Pass);
    }

    #[test]
    fn fail_when_output_mismatches_expected() {
        let v = vector(Some("0x010203"));
        let r = TestResult::from_run(&v, vec![9, 9, 9], 4, 12, 2, Duration::from_micros(50));
        assert_eq!(r.outcome, Outcome::Fail);
        assert!(r.note.as_ref().unwrap().contains("mismatch"));
    }

    #[test]
    fn should_pass_mismatch_is_a_warning_not_a_failure() {
        let v = vector_with_level(ConformanceLevel::ShouldPass, Some("0x010203"));
        let r = TestResult::from_run(&v, vec![9, 9, 9], 4, 12, 2, Duration::from_micros(50));
        assert_eq!(
            r.outcome,
            Outcome::Warn,
            "should_pass mismatch must downgrade to a warning"
        );
        assert!(r.note.as_ref().unwrap().contains("mismatch"));
    }

    #[test]
    fn informational_mismatch_is_a_pass() {
        let v = vector_with_level(ConformanceLevel::Informational, Some("0x010203"));
        let r = TestResult::from_run(&v, vec![9, 9, 9], 4, 12, 2, Duration::from_micros(50));
        assert_eq!(
            r.outcome,
            Outcome::Pass,
            "informational mismatch must never gate the candidate"
        );
        // The mismatch is still recorded in the note for the report.
        assert!(r.note.as_ref().unwrap().contains("mismatch"));
    }

    #[test]
    fn round_count_mismatch_on_passing_vector_is_a_warning() {
        let mut v = vector(None);
        v.expected_round_count = Some(3);
        let r = TestResult::from_run(&v, vec![1, 2, 3], 4, 12, 5, Duration::from_micros(50));
        assert_eq!(r.outcome, Outcome::Warn);
        assert!(r.note.as_ref().unwrap().contains("round count"));
    }

    #[test]
    fn outcome_warn_serializes_as_warn_string() {
        assert_eq!(Outcome::Warn.as_str(), "warn");
    }

    #[test]
    fn aborted_records_reason() {
        let v = vector(None);
        let r = TestResult::aborted(&v, "byzantine-drop detected", 1, Duration::from_micros(10));
        assert_eq!(r.outcome, Outcome::Aborted);
        assert_eq!(r.output.len(), 0);
        assert_eq!(r.note.as_deref(), Some("byzantine-drop detected"));
    }
}
