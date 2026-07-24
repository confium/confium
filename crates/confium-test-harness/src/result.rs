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
    /// caller supplies the produced output; this constructor decides
    /// `Pass` vs `Fail` by comparing against the vector's expected
    /// bytes (when present).
    pub fn from_run(
        vector: &TestVector,
        output: Vec<u8>,
        messages_exchanged: u64,
        bytes_exchanged: u64,
        rounds: u8,
        elapsed: Duration,
    ) -> Self {
        let (outcome, note) = match vector.test.expected_bytes() {
            Some(expected) if expected == output => (Outcome::Pass, None),
            Some(expected) => (
                Outcome::Fail,
                Some(format!(
                    "output mismatch: expected {} bytes, got {} bytes",
                    expected.len(),
                    output.len()
                )),
            ),
            // No expected bytes declared — completing is a pass.
            None => (Outcome::Pass, None),
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
        }
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
    fn aborted_records_reason() {
        let v = vector(None);
        let r = TestResult::aborted(&v, "byzantine-drop detected", 1, Duration::from_micros(10));
        assert_eq!(r.outcome, Outcome::Aborted);
        assert_eq!(r.output.len(), 0);
        assert_eq!(r.note.as_deref(), Some("byzantine-drop detected"));
    }
}
