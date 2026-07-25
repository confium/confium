//! TOML test-vector parser.
//!
//! A [`TestVector`] is the unit NIST hands to the harness: a scheme
//! name, the test parameters (parties, threshold, message, RNG seed),
//! optional expected-output bytes, and a list of per-party Byzantine
//! behaviors.
//!
//! The schema matches `TODO.roadmap/09-nist-evaluation-harness.md`:
//!
//! ```toml
//! [scheme]
//! name = "FROST-ed25519"
//! version = "draft-irtf-cfrg-frost-13"
//!
//! [test]
//! parties = 5
//! threshold = 3
//! message = "hello world"               # UTF-8 string OR "0x.."
//! seed = "0xdeadbeef..."                # hex seed for deterministic RNG
//! expected_signature_hex = "..."        # optional
//!
//! conformance_level = "must_pass"       # must_pass | should_pass | informational
//! reference = "https://..."             # normative spec URL
//! expected_round_count = 3              # warn if observed differs
//! share_material = "nist-dkg-set-A"     # named pre-shared share label
//!
//! [[peer_behavior]]
//! party_id = "alice"
//! type = "honest"
//! ```

use serde::Deserialize;

use crate::Result;
use crate::byzantine::{BehaviorSpec, PeerBehavior};
use crate::error;
use crate::error::VectorSnafu;

/// Conformance level declared by a vector. Mirrors NIST's
/// MUST/SHOULD/INFORMATIONAL classification: a `MustPass` failure is a
/// hard error; a `ShouldPass` failure is a warning (the scheme is
/// expected to comply but the failure is not disqualifying on its
/// own); `Informational` failures never count against the candidate.
///
/// Wire form is the lowercased tag in the vector's `[test]` block:
/// `must_pass`, `should_pass`, `informational`. Defaults to
/// `MustPass` when omitted so existing vectors keep their strict
/// semantics.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
pub enum ConformanceLevel {
    /// The candidate MUST pass this vector. A failure is a hard error
    /// and disqualifies the submission for this profile.
    #[default]
    #[serde(rename = "must_pass")]
    MustPass,
    /// The candidate SHOULD pass this vector. A failure is recorded as
    /// a warning; NIST may tolerate a bounded number of warnings.
    #[serde(rename = "should_pass")]
    ShouldPass,
    /// Informational only. The result is reported but never gates the
    /// candidate.
    #[serde(rename = "informational")]
    Informational,
}

impl ConformanceLevel {
    /// Map a tag string to a conformance level. Returns `None` for an
    /// unknown tag so the parser can surface a clear error.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "must_pass" => Some(ConformanceLevel::MustPass),
            "should_pass" => Some(ConformanceLevel::ShouldPass),
            "informational" => Some(ConformanceLevel::Informational),
            _ => None,
        }
    }

    /// Canonical wire tag for this level.
    pub fn as_tag(self) -> &'static str {
        match self {
            ConformanceLevel::MustPass => "must_pass",
            ConformanceLevel::ShouldPass => "should_pass",
            ConformanceLevel::Informational => "informational",
        }
    }
}

/// Top-level TOML document.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TestVector {
    pub scheme: SchemeSpec,
    pub test: TestVectorTest,
    #[serde(default)]
    pub peer_behavior: Vec<PeerBehaviorEntry>,
    /// NIST-style conformance classification for this vector. Defaults
    /// to `MustPass` when absent so the schema remains strict-by-default.
    #[serde(default)]
    pub conformance_level: ConformanceLevel,
    /// Optional URL pointing at the normative reference (spec section,
    /// RFC, NIST publication) this vector exercises. Carried through to
    /// the report so NIST can attribute every measurement to its source.
    #[serde(default)]
    pub reference: Option<String>,
    /// Optional: the number of rounds a compliant implementation is
    /// expected to take. When set, the runner warns if the observed
    /// round count differs (but never fails on it alone).
    #[serde(default)]
    pub expected_round_count: Option<u8>,
    /// Optional: the label of the pre-shared key material to feed into
    /// each party's `local_share`. NIST publishes named DKG outputs;
    /// this field lets a vector reference them by name rather than
    /// inlining bytes. The harness resolves the label to bytes via the
    /// environment (test fixture or registry lookup).
    #[serde(default)]
    pub share_material: Option<String>,
}

/// `[scheme]` block: identity of the candidate under test.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SchemeSpec {
    pub name: String,
    #[serde(default)]
    pub version: String,
}

/// `[test]` block: harness inputs.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TestVectorTest {
    pub parties: u32,
    pub threshold: u32,
    /// UTF-8 message, or `"0x..."` for binary. Either form decodes to
    /// raw bytes via [`TestVectorTest::message_bytes`].
    #[serde(default)]
    pub message: String,
    /// Hex seed (`"0xdeadbeef"`) for the deterministic RNG.
    #[serde(default)]
    pub seed: String,
    /// Optional expected signature / output, hex-encoded.
    #[serde(default)]
    pub expected_signature_hex: String,
}

/// One `[[peer_behavior]]` entry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PeerBehaviorEntry {
    pub party_id: String,
    /// Tag string: `"honest"`, `"byzantine-drop"`, etc. Validated
    /// against [`PeerBehavior::from_tag`] during parse.
    #[serde(rename = "type")]
    pub behavior_tag: String,
    /// Optional: which round a `byzantine-drop` peer drops in.
    #[serde(default)]
    pub drop_round: Option<u8>,
}

impl TestVector {
    /// Parse a TOML document. Validates behaviors and decodes seed/message.
    pub fn parse(toml_str: &str) -> Result<Self> {
        let raw: TestVector = toml::from_str(toml_str).map_err(|e| {
            error::VectorSnafu {
                message: e.to_string(),
            }
            .build()
        })?;
        raw.validate()?;
        Ok(raw)
    }

    /// Read and parse a vector from a file path.
    pub fn from_path(path: &std::path::Path) -> Result<Self> {
        let body = std::fs::read_to_string(path).map_err(|e| {
            VectorSnafu {
                message: format!("could not read {}: {}", path.display(), e),
            }
            .build()
        })?;
        Self::parse(&body)
    }

    fn validate(&self) -> Result<()> {
        if self.test.parties == 0 {
            return Err(VectorSnafu {
                message: "[test] parties must be at least 1".to_string(),
            }
            .build());
        }
        if self.test.threshold == 0 {
            return Err(VectorSnafu {
                message: "[test] threshold must be at least 1".to_string(),
            }
            .build());
        }
        if self.test.threshold > self.test.parties {
            return Err(VectorSnafu {
                message: format!(
                    "[test] threshold {} exceeds parties {}",
                    self.test.threshold, self.test.parties
                ),
            }
            .build());
        }
        // Every behavior tag must be known.
        for entry in &self.peer_behavior {
            if PeerBehavior::from_tag(&entry.behavior_tag).is_none() {
                return Err(VectorSnafu {
                    message: format!(
                        "unknown peer_behavior type '{}' for party '{}'",
                        entry.behavior_tag, entry.party_id
                    ),
                }
                .build());
            }
        }
        if let Some(rc) = self.expected_round_count {
            if rc == 0 {
                return Err(VectorSnafu {
                    message: "expected_round_count must be at least 1".to_string(),
                }
                .build());
            }
        }
        Ok(())
    }

    /// Decode the seed field into a `u64`. Accepts `"0x..."` hex or bare
    /// hex; empty defaults to 0.
    pub fn seed_u64(&self) -> Result<u64> {
        decode_hex_u64(&self.test.seed).ok_or_else(|| {
            VectorSnafu {
                message: format!("could not decode seed '{}' as hex u64", self.test.seed),
            }
            .build()
        })
    }

    /// Convert the parsed vector into [`BehaviorSpec`]s for the
    /// [`crate::ByzantineTransport`].
    pub fn behavior_specs(&self) -> Vec<BehaviorSpec> {
        self.peer_behavior
            .iter()
            .map(|entry| BehaviorSpec {
                party_id: entry.party_id.clone(),
                behavior: PeerBehavior::from_tag(&entry.behavior_tag)
                    .unwrap_or(PeerBehavior::Honest),
                drop_round: entry.drop_round,
            })
            .collect()
    }
}

impl TestVectorTest {
    /// Decode `message` to raw bytes. `"0x..."` is hex; anything else is
    /// the literal UTF-8 bytes of the string.
    pub fn message_bytes(&self) -> Vec<u8> {
        if let Some(rest) = self.message.strip_prefix("0x") {
            decode_hex_bytes(rest).unwrap_or_else(|| self.message.as_bytes().to_vec())
        } else {
            self.message.as_bytes().to_vec()
        }
    }

    /// Decode the expected-output hex into bytes, if present.
    pub fn expected_bytes(&self) -> Option<Vec<u8>> {
        if self.expected_signature_hex.is_empty() {
            return None;
        }
        let stripped = self
            .expected_signature_hex
            .strip_prefix("0x")
            .unwrap_or(&self.expected_signature_hex);
        decode_hex_bytes(stripped)
    }
}

/// Parse a hex u64, accepting an optional `0x` prefix.
fn decode_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 16).ok()
}

/// Decode a hex string (no `0x` prefix) into bytes. Returns `None` on
/// odd length or non-hex digits.
fn decode_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../vectors/sample.toml");

    #[test]
    fn sample_parses_correctly() {
        let v = TestVector::parse(SAMPLE).expect("sample.toml must parse");
        assert_eq!(v.scheme.name, "FROST-ed25519");
        assert_eq!(v.scheme.version, "draft-irtf-cfrg-frost-13");
        assert_eq!(v.test.parties, 5);
        assert_eq!(v.test.threshold, 3);
        assert_eq!(v.test.message_bytes(), b"hello world");
        assert_eq!(v.peer_behavior.len(), 3);
        assert_eq!(v.peer_behavior[0].party_id, "alice");
        assert_eq!(v.peer_behavior[0].behavior_tag, "honest");
        assert_eq!(v.peer_behavior[2].behavior_tag, "byzantine-drop");
    }

    #[test]
    fn seed_decodes_as_hex_u64() {
        let v = TestVector::parse(SAMPLE).unwrap();
        assert_eq!(v.seed_u64().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn behavior_specs_round_trip() {
        let v = TestVector::parse(SAMPLE).unwrap();
        let specs = v.behavior_specs();
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[2].behavior, PeerBehavior::Drop);
        assert_eq!(specs[2].drop_round, Some(2));
    }

    #[test]
    fn rejects_zero_parties() {
        let bad = r#"
[scheme]
name = "x"
version = "1"
[test]
parties = 0
threshold = 1
"#;
        assert!(TestVector::parse(bad).is_err());
    }

    #[test]
    fn rejects_threshold_above_parties() {
        let bad = r#"
[scheme]
name = "x"
[test]
parties = 2
threshold = 5
"#;
        assert!(TestVector::parse(bad).is_err());
    }

    #[test]
    fn rejects_unknown_behavior_tag() {
        let bad = r#"
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
[[peer_behavior]]
party_id = "a"
type = "byzantine-flip-table"
"#;
        let err = TestVector::parse(bad).unwrap_err();
        assert!(format!("{err}").contains("unknown peer_behavior type"));
    }

    #[test]
    fn binary_message_via_hex_prefix() {
        let v = TestVector::parse(
            r#"
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
message = "0xdeadbeef"
"#,
        )
        .unwrap();
        assert_eq!(v.test.message_bytes(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn expected_signature_decodes_when_present() {
        let v = TestVector::parse(
            r#"
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
expected_signature_hex = "0x01020304"
"#,
        )
        .unwrap();
        assert_eq!(v.test.expected_bytes(), Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn expected_signature_absent_when_empty() {
        let v = TestVector::parse(
            r#"
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
"#,
        )
        .unwrap();
        assert!(v.test.expected_bytes().is_none());
    }

    #[test]
    fn conformance_level_defaults_to_must_pass() {
        let v = TestVector::parse(
            r#"
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
"#,
        )
        .unwrap();
        assert_eq!(v.conformance_level, ConformanceLevel::MustPass);
    }

    #[test]
    fn conformance_level_parses_should_pass() {
        let v = TestVector::parse(
            r#"
conformance_level = "should_pass"
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
"#,
        )
        .unwrap();
        assert_eq!(v.conformance_level, ConformanceLevel::ShouldPass);
    }

    #[test]
    fn conformance_level_parses_informational() {
        let v = TestVector::parse(
            r#"
conformance_level = "informational"
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
"#,
        )
        .unwrap();
        assert_eq!(v.conformance_level, ConformanceLevel::Informational);
    }

    #[test]
    fn conformance_level_rejects_unknown_tag_with_useful_error() {
        let bad = r#"
conformance_level = "maybe_pass"
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
"#;
        let err = TestVector::parse(bad).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("conformance_level") || msg.contains("maybe_pass"),
            "error must point at the bad conformance_level tag: {msg}"
        );
    }

    #[test]
    fn reference_and_share_material_parse() {
        let v = TestVector::parse(
            r#"
reference = "https://example.org/spec"
share_material = "nist-dkg-A"
expected_round_count = 4
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
"#,
        )
        .unwrap();
        assert_eq!(v.reference.as_deref(), Some("https://example.org/spec"));
        assert_eq!(v.share_material.as_deref(), Some("nist-dkg-A"));
        assert_eq!(v.expected_round_count, Some(4));
    }

    #[test]
    fn rejects_zero_expected_round_count() {
        let bad = r#"
expected_round_count = 0
[scheme]
name = "x"
[test]
parties = 2
threshold = 1
"#;
        let err = TestVector::parse(bad).unwrap_err();
        assert!(
            format!("{err}").contains("expected_round_count"),
            "error must name the offending field"
        );
    }

    #[test]
    fn malformed_toml_surfaces_useful_error() {
        // Missing the [scheme] table entirely — toml::from_str rejects
        // this, and the parser must relay that as a Vector error
        // (not a panic, not a raw toml::de::Error).
        let bad = "this is not toml at all {{{";
        let err = TestVector::parse(bad).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("malformed") || msg.contains("expected"),
            "error must describe the malformation: {msg}"
        );
    }

    #[test]
    fn missing_scheme_name_surfaces_useful_error() {
        // A structurally-valid TOML document that is missing a required
        // field. The error must name what is missing.
        let bad = r#"
[scheme]
[test]
parties = 2
threshold = 1
"#;
        let err = TestVector::parse(bad).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("name") || msg.contains("scheme"),
            "error must point at the missing scheme.name: {msg}"
        );
    }

    #[test]
    fn conformance_level_round_trips_through_tags() {
        for level in [
            ConformanceLevel::MustPass,
            ConformanceLevel::ShouldPass,
            ConformanceLevel::Informational,
        ] {
            let tag = level.as_tag();
            assert_eq!(ConformanceLevel::from_tag(tag), Some(level));
        }
    }
}
