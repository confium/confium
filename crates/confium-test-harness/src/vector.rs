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
//! [[peer_behavior]]
//! party_id = "alice"
//! type = "honest"
//! ```

use serde::Deserialize;

use crate::Result;
use crate::byzantine::{BehaviorSpec, PeerBehavior};
use crate::error;
use crate::error::VectorSnafu;

/// Top-level TOML document.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TestVector {
    pub scheme: SchemeSpec,
    pub test: TestVectorTest,
    #[serde(default)]
    pub peer_behavior: Vec<PeerBehaviorEntry>,
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
}
