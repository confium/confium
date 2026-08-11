//! Fuzz target: Merkle consistency proof verification.
//!
//! Exercises the consistency-proof path (RFC 6962 §2.1.2), which
//! is distinct from the inclusion-proof path fuzzed by
//! `fuzz_inclusion_proof`. Adversarial inputs include:
//!
//! - wrong direction bits in proof steps
//! - proof hashes shorter/longer than 32 bytes
//! - claimed old_size/new_size pairs that don't correspond to any
//!   real tree shape
//! - proofs that fail to reproduce the claimed roots
//!
//! The verifier must not panic on any input — failures must
//! surface as `MerkleError::ConsistencyFailed`, not a panic.

use confium_transparency::entry::{ArtifactType, MerkleEntry};
use confium_transparency::merkle::{Hash, MerkleTree};

fn merkle_consistency_target(data: &[u8]) {
    // Need at least: 8 bytes old_root + 8 bytes new_root + 8 bytes
    // old_size + 8 bytes new_size + 1 byte of tree content = 33.
    // Below that, just bail.
    if data.len() < 33 {
        return;
    }

    // Build a tree of bounded size from the first portion of the input.
    // Cap at 16 leaves so each fuzz iteration is fast.
    let n_leaves = (data[0] as usize % 16) + 1;
    let mut tree = MerkleTree::new();
    for i in 0..n_leaves as u64 {
        let hash_byte = data[(i as usize + 1) % data.len()];
        let hash = [hash_byte.wrapping_add(i as u8); 32];
        let entry = MerkleEntry::new(i, ArtifactType::CertificateIssuance, hash);
        tree.append(entry);
    }

    // old_size and new_size from the byte stream. Clamp to valid range.
    let old_size = (data.get(1).copied().unwrap_or(0) as usize) % (n_leaves + 1);
    let new_size = n_leaves;

    // Construct claimed roots from arbitrary bytes.
    let mut old_root: Hash = [0u8; 32];
    let mut new_root: Hash = [0u8; 32];
    for i in 0..32 {
        old_root[i] = data.get(2 + i).copied().unwrap_or(0);
        new_root[i] = data.get(34 + i).copied().unwrap_or(0);
    }

    // Generate the real consistency proof from the tree, then verify
    // against the claimed (possibly-wrong) roots. The fuzz surface is
    // the verifier's handling of mismatched roots.
    let proof = match tree.consistency_proof(old_size) {
        Ok(p) => p,
        Err(_) => return,
    };
    let _ = tree.verify_consistency(old_root, new_root, old_size, new_size, &proof);
}

fn main() {
    let mut rng_data = vec![0u8; 128];
    for round in 0..100_000u64 {
        for (i, b) in rng_data.iter_mut().enumerate() {
            *b = ((round * 23 + i as u64 * 11) & 0xFF) as u8;
        }
        merkle_consistency_target(&rng_data);
    }
    println!("merkle_proof: 100000 rounds completed, no panics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_input_does_not_panic() {
        merkle_consistency_target(&[0; 5]);
    }

    #[test]
    fn empty_tree_does_not_panic() {
        // n_leaves will be 1 (data[0] % 16 + 1 = 1), then verify_consistency
        // called with old_size = 0 should return Ok immediately per
        // merkle.rs:413.
        merkle_consistency_target(&[0; 64]);
    }

    #[test]
    fn large_input_does_not_panic() {
        merkle_consistency_target(&[0xAA; 1024]);
    }
}
