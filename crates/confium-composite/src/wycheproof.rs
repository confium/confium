//! Wycheproof test vector integration.
//!
//! [Wycheproof](https://github.com/google/wycheproof) is Google's
//! suite of adversarial test vectors for cryptographic primitives.
//! It has found bugs in nearly every widely-used crypto library.
//! This module wires the ECDSA-P256 / Ed25519 vectors into our
//! verifier surface so we can prove (and continuously re-prove)
//! that our verification code accepts good signatures and rejects
//! malformed ones.
//!
//! ## How to run
//!
//! ```sh
//! # 1. Download the test vectors:
//! curl -L https://raw.githubusercontent.com/google/wycheproof/master/testvectors_v1/ecdsa_secp256r1_sha256_test.json \
//!     -o /tmp/wycheproof/ecdsa_secp256r1_sha256_test.json
//! curl -L https://raw.githubusercontent.com/google/wycheproof/master/testvectors_v1/ed25519_test.json \
//!     -o /tmp/wycheproof/ed25519_test.json
//!
//! # 2. Run the harness (skips the real-vector test when the
//! #    directory is unset):
//! WYCHEPROOF_VECTORS_DIR=/tmp/wycheproof \
//!     cargo test --features wycheproof -p confium-composite wycheproof
//! ```
//!
//! ## What it checks
//!
//! - **Valid signatures** (result `valid`): must verify. A failure
//!   here means we reject good signatures.
//! - **Invalid signatures** (result `invalid`): must be rejected. A
//!   failure here means we accept bad signatures — a security bug.
//! - **Acceptable** (result `acceptable`): degenerate cases where
//!   verifying or rejecting are both defensible (e.g. signature
//!   value `s = 0`); either outcome counts as acceptable.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct WycheproofFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    /// The group's public key; ECDSA groups carry an uncompressed
    /// SEC1 point, EdDSA groups a raw key.
    #[serde(rename = "publicKey")]
    public_key: Option<GroupKey>,
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct GroupKey {
    /// ECDSA: uncompressed SEC1 point (`0x04 || x || y`), hex.
    #[serde(default)]
    uncompressed: Option<String>,
    /// EdDSA: raw public key, hex.
    #[serde(default)]
    pk: Option<String>,
}

impl GroupKey {
    fn bytes(&self) -> Option<Vec<u8>> {
        if let Some(point) = &self.uncompressed {
            return hex::decode(point).ok();
        }
        self.pk.as_ref().and_then(|pk| hex::decode(pk).ok())
    }
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u64,
    comment: String,
    msg: String,    // hex
    sig: String,    // hex (DER for ECDSA)
    result: String, // "valid" | "invalid" | "acceptable"
}

/// The outcome of one vector-file run. `failed` is the number that
/// matters: zero means the verifier matched every expectation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Cases where the verifier matched the vector's expectation.
    pub passed: usize,
    /// Cases where it did not — each entry is named in `failures`.
    pub failed: usize,
    /// Degenerate cases where verify or reject are both defensible.
    pub acceptable: usize,
    /// One human-readable line per failed case.
    pub failures: Vec<String>,
}

/// Run every case in a Wycheproof vector file through `verifier`,
/// which takes `(public_key, message, signature)`. An unreadable or
/// malformed file yields an all-zero [`Summary`].
pub fn run_vectors(path: &Path, verifier: impl Fn(&[u8], &[u8], &[u8]) -> bool) -> Summary {
    let Some(file) = load(path) else {
        return Summary::default();
    };
    let mut summary = Summary::default();
    for group in &file.test_groups {
        let Some(public_key) = group.public_key.as_ref().and_then(GroupKey::bytes) else {
            continue;
        };
        for tc in &group.tests {
            let (Ok(msg), Ok(sig)) = (hex::decode(&tc.msg), hex::decode(&tc.sig)) else {
                continue;
            };
            let actual = verifier(&public_key, &msg, &sig);
            match tc.result.as_str() {
                "acceptable" => summary.acceptable += 1,
                "valid" | "invalid" => {
                    let expected = tc.result == "valid";
                    if actual == expected {
                        summary.passed += 1;
                    } else {
                        summary.failed += 1;
                        summary.failures.push(format!(
                            "tcId {} ({}): expected {}, verifier returned {}",
                            tc.tc_id, tc.comment, expected, actual
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    summary
}

/// Load a Wycheproof JSON file. `None` if unreadable or malformed.
fn load(path: &Path) -> Option<WycheproofFile> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Compatibility wrapper for the original scaffold's signature,
/// returning `(passed, failed, acceptable)`.
#[deprecated(
    since = "0.6.0",
    note = "use run_vectors, which also reports failing tcIds"
)]
pub fn run_ecdsa_p256(
    path: &Path,
    verifier: impl Fn(&[u8], &[u8], &[u8]) -> bool,
) -> (usize, usize, usize) {
    let summary = run_vectors(path, verifier);
    (summary.passed, summary.failed, summary.acceptable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn verifier(alg: &str) -> impl Fn(&[u8], &[u8], &[u8]) -> bool + '_ {
        move |pk, msg, sig| {
            if alg == crate::ED25519 {
                crate::ed25519_verifier(alg, pk, msg, sig).is_ok()
            } else {
                crate::p256_verifier(alg, pk, msg, sig).is_ok()
            }
        }
    }

    fn write_vectors(name: &str, body: String) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("confium-wycheproof-{name}.json"));
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn missing_file_yields_zeroes() {
        assert_eq!(
            run_vectors(Path::new("/nonexistent"), verifier(crate::ED25519)),
            Summary::default()
        );
    }

    #[test]
    fn malformed_file_yields_zeroes() {
        let path = write_vectors("malformed", "not json".to_string());
        assert_eq!(
            run_vectors(&path, verifier(crate::ED25519)),
            Summary::default()
        );
    }

    #[test]
    fn group_without_key_is_skipped() {
        let path = write_vectors(
            "no-key",
            r#"{"testGroups":[{"tests":[
                {"tcId":1,"comment":"","msg":"00","sig":"00","result":"valid"}
            ]}]}"#
                .to_string(),
        );
        assert_eq!(
            run_vectors(&path, verifier(crate::ED25519)),
            Summary::default()
        );
    }

    #[test]
    fn vectors_are_actually_verified() {
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let good_sig = sk.sign(b"hello").to_bytes();
        let mut bad_sig = good_sig;
        bad_sig[0] ^= 1;

        let body = format!(
            r#"{{"testGroups":[{{"publicKey":{{"pk":"{}"}},"tests":[
                {{"tcId":1,"comment":"good sig labelled valid","msg":"{}","sig":"{}","result":"valid"}},
                {{"tcId":2,"comment":"good sig mislabelled invalid","msg":"{}","sig":"{}","result":"invalid"}},
                {{"tcId":3,"comment":"bad sig labelled valid","msg":"{}","sig":"{}","result":"valid"}},
                {{"tcId":4,"comment":"bad sig labelled invalid","msg":"{}","sig":"{}","result":"invalid"}},
                {{"tcId":5,"comment":"acceptable either way","msg":"{}","sig":"00","result":"acceptable"}}
            ]}}]}}"#,
            hex::encode(sk.verifying_key().as_bytes()),
            hex::encode(b"hello"),
            hex::encode(good_sig),
            hex::encode(b"hello"),
            hex::encode(good_sig),
            hex::encode(b"hello"),
            hex::encode(bad_sig),
            hex::encode(b"hello"),
            hex::encode(bad_sig),
            hex::encode(b"hello"),
        );
        let path = write_vectors("ed25519", body);

        let summary = run_vectors(&path, verifier(crate::ED25519));
        assert_eq!(summary.passed, 2, "{summary:?}"); // tc 1, 4
        assert_eq!(summary.failed, 2, "{summary:?}"); // tc 2, 3
        assert_eq!(summary.acceptable, 1, "{summary:?}"); // tc 5
        assert_eq!(summary.failures.len(), 2);
        assert!(summary.failures[0].contains("tcId 2"), "{summary:?}");
        assert!(summary.failures[1].contains("tcId 3"), "{summary:?}");
    }

    /// Runs the real Google vectors when `WYCHEPROOF_VECTORS_DIR`
    /// points at a directory containing the downloaded files; skips
    /// otherwise (the ~1 MB of JSON is not vendored).
    #[test]
    fn real_vectors_when_downloaded() {
        let Ok(dir) = std::env::var("WYCHEPROOF_VECTORS_DIR") else {
            eprintln!("skipping: WYCHEPROOF_VECTORS_DIR is not set");
            return;
        };
        let dir = std::path::PathBuf::from(dir);

        let ecdsa = dir.join("ecdsa_secp256r1_sha256_test.json");
        if ecdsa.exists() {
            let summary = run_vectors(&ecdsa, verifier(crate::ECDSA_P256));
            assert!(summary.passed > 0, "no ECDSA cases ran: {summary:?}");
            assert_eq!(summary.failed, 0, "ECDSA P256: {summary:?}");
        } else {
            eprintln!("skipping: {} not found", ecdsa.display());
        }

        let eddsa = dir.join("ed25519_test.json");
        if eddsa.exists() {
            let summary = run_vectors(&eddsa, verifier(crate::ED25519));
            assert!(summary.passed > 0, "no Ed25519 cases ran: {summary:?}");
            assert_eq!(summary.failed, 0, "Ed25519: {summary:?}");
        } else {
            eprintln!("skipping: {} not found", eddsa.display());
        }
    }
}
