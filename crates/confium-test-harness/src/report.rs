//! JSON report writer for NIST submission.
//!
//! NIST MPTS consumes machine-readable JSON: one entry per vector run,
//! each carrying the scheme identity, pass/fail outcome, message and
//! byte tallies, round count, and elapsed time. The harness produces
//! raw measurements only — Confium does not score or rank; NIST decides
//! what the numbers mean (see `09-nist-evaluation-harness.md`:
//! "Anti-goals").
//!
//! [`Report`] is a thin typed wrapper over a `Vec<ReportEntry>`; call
//! [`Report::to_json`] for the string NIST expects, or
//! [`Report::to_json_pretty`] for a human-friendly variant.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::TestResult;

/// One row in the output report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportEntry {
    pub scheme_name: String,
    pub scheme_version: String,
    pub parties: u32,
    pub threshold: u32,
    pub outcome: String,
    pub output_hex: String,
    pub messages_exchanged: u64,
    pub bytes_exchanged: u64,
    pub rounds: u8,
    pub elapsed_nanos: u128,
    pub note: Option<String>,
}

impl From<&TestResult> for ReportEntry {
    fn from(r: &TestResult) -> Self {
        ReportEntry {
            scheme_name: r.scheme_name.clone(),
            scheme_version: r.scheme_version.clone(),
            parties: r.parties,
            threshold: r.threshold,
            outcome: r.outcome.as_str().to_string(),
            output_hex: to_hex(&r.output),
            messages_exchanged: r.messages_exchanged,
            bytes_exchanged: r.bytes_exchanged,
            rounds: r.rounds,
            elapsed_nanos: r.elapsed.as_nanos(),
            note: r.note.clone(),
        }
    }
}

/// A batch of vector results, serializable as the JSON NIST ingests.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub entries: Vec<ReportEntry>,
}

impl Report {
    pub fn new() -> Self {
        Report::default()
    }

    pub fn from_results(results: &[TestResult]) -> Self {
        Report {
            entries: results.iter().map(ReportEntry::from).collect(),
        }
    }

    pub fn push(&mut self, entry: ReportEntry) {
        self.entries.push(entry);
    }

    /// Compact JSON — one line of header + entries. NIST's ingestion
    /// pipeline handles either form; this is the default.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Pretty-printed JSON for human review.
    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Lowercase hex encoding without pulling in a dedicated crate.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Outcome;
    use std::time::Duration;

    fn fake_result(outcome: Outcome) -> TestResult {
        TestResult {
            scheme_name: "FROST-ed25519".into(),
            scheme_version: "draft-irtf-cfrg-frost-13".into(),
            parties: 5,
            threshold: 3,
            outcome,
            output: vec![0xDE, 0xAD],
            messages_exchanged: 12,
            bytes_exchanged: 1024,
            rounds: 3,
            elapsed: Duration::from_micros(12_345),
            note: None,
        }
    }

    #[test]
    fn entry_serializes_to_expected_fields() {
        let r = fake_result(Outcome::Pass);
        let entry = ReportEntry::from(&r);
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"scheme_name\":\"FROST-ed25519\""));
        assert!(json.contains("\"outcome\":\"pass\""));
        assert!(json.contains("\"output_hex\":\"dead\""));
        assert!(json.contains("\"messages_exchanged\":12"));
        assert!(json.contains("\"rounds\":3"));
    }

    #[test]
    fn report_round_trips_through_json() {
        let report =
            Report::from_results(&[fake_result(Outcome::Pass), fake_result(Outcome::Fail)]);
        let json = report.to_json().unwrap();
        let reparsed: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(reparsed.entries.len(), 2);
        assert_eq!(reparsed.entries[0].outcome, "pass");
        assert_eq!(reparsed.entries[1].outcome, "fail");
    }

    #[test]
    fn pretty_json_is_multiline() {
        let report = Report::from_results(&[fake_result(Outcome::Pass)]);
        let pretty = report.to_json_pretty().unwrap();
        assert!(pretty.contains('\n'));
    }

    #[test]
    fn to_hex_lowercase_no_prefix() {
        assert_eq!(to_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(to_hex(&[]), "");
    }
}
