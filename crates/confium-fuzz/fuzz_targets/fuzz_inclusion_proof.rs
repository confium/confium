//! Fuzz target: transparency log inclusion proof verification.
//!
//! Exercises the Merkle tree inclusion proof verification with
//! arbitrary hash bytes. The target must not panic.

use confium_transparency::entry::{ArtifactType, MerkleEntry};
use confium_transparency::merkle::{Hash, InclusionProof, MerkleTree, ProofStep, Side};

fn inclusion_proof_target(data: &[u8]) {
    if data.len() < 32 {
        return;
    }
    let (root_bytes, rest) = data.split_at(32);
    let mut root: Hash = [0u8; 32];
    root.copy_from_slice(root_bytes);

    let entry = MerkleEntry::new(0, ArtifactType::ThresholdSignature, [rest.first().copied().unwrap_or(0); 32]);

    let steps: Vec<ProofStep> = rest
        .chunks(33)
        .take(32)
        .filter(|c| c.len() == 33)
        .map(|c| {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&c[0..32]);
            let side = if c[32] & 1 == 0 { Side::Left } else { Side::Right };
            ProofStep { sibling: hash, side }
        })
        .collect();

    let proof = InclusionProof { sequence: 0, steps };
    let _ = MerkleTree::verify_inclusion(&entry, &proof, root);
}

fn main() {
    let mut rng_data = vec![0u8; 512];
    for round in 0..100_000u64 {
        for (i, b) in rng_data.iter_mut().enumerate() {
            *b = ((round * 37 + i as u64 * 13) & 0xFF) as u8;
        }
        inclusion_proof_target(&rng_data);
    }
    println!("inclusion_proof: 100000 rounds completed, no panics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_input_does_not_panic() {
        inclusion_proof_target(&[0; 10]);
    }

    #[test]
    fn empty_steps_does_not_panic() {
        let mut root = [0u8; 32];
        root.copy_from_slice(&[0xFF; 32]);
        let entry = MerkleEntry::new(0, ArtifactType::ThresholdSignature, [0; 32]);
        let proof = InclusionProof { sequence: 0, steps: vec![] };
        let _ = MerkleTree::verify_inclusion(&entry, &proof, root);
    }

    #[test]
    fn large_input_does_not_panic() {
        inclusion_proof_target(&[0xAA; 2048]);
    }
}
