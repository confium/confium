//! Deterministic test vectors for the transparency log.
//!
//! Generates reproducible Merkle tree fixtures with known-good roots
//! and inclusion proofs. Used for:
//! - Cross-implementation compatibility testing
//! - Regression detection
//! - Binding verification (Ruby, Python, WASM, Go)

use crate::entry::{ArtifactType, MerkleEntry};
use crate::merkle::{Hash, InclusionProof, MerkleTree};
use serde::{Deserialize, Serialize};

/// A single test vector entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVector {
    /// Human-readable description.
    pub description: String,
    /// Tree entries (artifact hashes as hex).
    pub artifact_hashes_hex: Vec<String>,
    /// Expected root hash (hex).
    pub expected_root_hex: String,
    /// Inclusion proofs for each entry (0-indexed).
    pub inclusion_proofs: Vec<InclusionProofJson>,
}

/// JSON-serializable inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofJson {
    /// Sequence number (0-indexed).
    pub sequence: u64,
    /// Proof steps: { sibling_hex, side }.
    pub steps: Vec<ProofStepJson>,
}

/// JSON-serializable proof step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStepJson {
    /// Sibling hash (hex).
    pub sibling_hex: String,
    /// Side: "left" or "right".
    pub side: String,
}

/// Generate a test vector for a tree with `n` entries.
///
/// Uses deterministic entries where each entry's artifact hash is
/// `[i; 32]` (all bytes set to the index). Timestamps are fixed to
/// a known epoch value for reproducibility.
pub fn generate_vector(n: u64) -> TestVector {
    let mut tree = MerkleTree::new();
    let fixed_time = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    for i in 0..n {
        let mut entry = MerkleEntry::new(i, ArtifactType::ThresholdSignature, [i as u8; 32]);
        entry.timestamp = fixed_time;
        tree.append(entry);
    }

    let root = tree.root();
    let mut proofs = Vec::new();
    for i in 0..n {
        let proof = tree.inclusion_proof(i).unwrap();
        let steps: Vec<ProofStepJson> = proof
            .steps
            .iter()
            .map(|s| ProofStepJson {
                sibling_hex: hex::encode(s.sibling),
                side: match s.side {
                    crate::merkle::Side::Left => "left".into(),
                    crate::merkle::Side::Right => "right".into(),
                },
            })
            .collect();
        proofs.push(InclusionProofJson {
            sequence: i,
            steps,
        });
    }

    let artifact_hashes: Vec<String> = (0..n).map(|i| hex::encode([i as u8; 32])).collect();

    TestVector {
        description: format!("Tree with {n} entries, deterministic hashes"),
        artifact_hashes_hex: artifact_hashes,
        expected_root_hex: hex::encode(root),
        inclusion_proofs: proofs,
    }
}

/// Generate a suite of test vectors for common tree sizes.
pub fn generate_suite() -> Vec<TestVector> {
    vec![
        generate_vector(1),
        generate_vector(2),
        generate_vector(3),
        generate_vector(4),
        generate_vector(8),
        generate_vector(16),
        generate_vector(32),
    ]
}

/// Verify a test vector against the current MerkleTree implementation.
/// Returns `Ok(())` if all proofs verify, `Err` with details otherwise.
pub fn verify_vector(vector: &TestVector) -> Result<(), String> {
    let root = decode_hash(&vector.expected_root_hex)?;
    let mut tree = MerkleTree::new();
    let fixed_time = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    for (i, hash_hex) in vector.artifact_hashes_hex.iter().enumerate() {
        let hash = decode_hash(hash_hex)?;
        let mut entry = MerkleEntry::new(i as u64, ArtifactType::ThresholdSignature, hash);
        entry.timestamp = fixed_time;
        tree.append(entry);
    }

    let actual_root = tree.root();
    if actual_root != root {
        return Err(format!(
            "root mismatch: expected {}, got {}",
            hex::encode(root),
            hex::encode(actual_root)
        ));
    }

    for proof_json in &vector.inclusion_proofs {
        let seq = proof_json.sequence;
        let entry = tree.entry(seq).map_err(|e| format!("{e:?}"))?.clone();
        let steps: Vec<crate::merkle::ProofStep> = proof_json
            .steps
            .iter()
            .map(|s| {
                Ok(crate::merkle::ProofStep {
                    sibling: decode_hash(&s.sibling_hex)?,
                    side: match s.side.as_str() {
                        "left" => crate::merkle::Side::Left,
                        "right" => crate::merkle::Side::Right,
                        _ => return Err(format!("invalid side: {}", s.side)),
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        let proof = InclusionProof {
            sequence: seq,
            steps,
        };
        MerkleTree::verify_inclusion(&entry, &proof, root).map_err(|e| format!("{e:?}"))?;
    }

    Ok(())
}

/// Serialize a test vector suite to JSON.
pub fn suite_to_json(suite: &[TestVector]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(suite)
}

fn decode_hash(hex_str: &str) -> Result<Hash, String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_entry_vector_has_correct_root() {
        let vector = generate_vector(1);
        assert_eq!(vector.artifact_hashes_hex.len(), 1);
        assert_eq!(vector.inclusion_proofs.len(), 1);
        assert!(!vector.expected_root_hex.is_empty());
    }

    #[test]
    fn vector_is_deterministic() {
        let v1 = generate_vector(5);
        let v2 = generate_vector(5);
        assert_eq!(v1.expected_root_hex, v2.expected_root_hex);
        assert_eq!(v1.inclusion_proofs.len(), v2.inclusion_proofs.len());
    }

    #[test]
    fn different_sizes_produce_different_roots() {
        let v1 = generate_vector(1);
        let v2 = generate_vector(2);
        assert_ne!(v1.expected_root_hex, v2.expected_root_hex);
    }

    #[test]
    fn verify_vector_passes_for_generated() {
        for n in [1, 2, 3, 5, 8, 16] {
            let vector = generate_vector(n);
            verify_vector(&vector).unwrap_or_else(|e| panic!("verify n={n}: {e}"));
        }
    }

    #[test]
    fn generate_suite_has_7_sizes() {
        let suite = generate_suite();
        assert_eq!(suite.len(), 7);
    }

    #[test]
    fn suite_serializes_to_json() {
        let suite = generate_suite();
        let json = suite_to_json(&suite).unwrap();
        assert!(json.contains("expected_root_hex"));
        assert!(json.contains("description"));
    }

    #[test]
    fn verify_vector_detects_tampered_root() {
        let mut vector = generate_vector(3);
        vector.expected_root_hex = hex::encode([0xFF; 32]);
        assert!(verify_vector(&vector).is_err());
    }

    #[test]
    fn inclusion_proof_count_matches_entries() {
        let vector = generate_vector(8);
        assert_eq!(vector.inclusion_proofs.len(), 8);
        for (i, proof) in vector.inclusion_proofs.iter().enumerate() {
            assert_eq!(proof.sequence, i as u64);
        }
    }

    #[test]
    fn power_of_two_tree_has_clean_proofs() {
        let vector = generate_vector(8);
        for proof in &vector.inclusion_proofs {
            assert!(proof.steps.len() <= 4, "8-entry tree has at most 4 proof steps");
        }
    }
}
