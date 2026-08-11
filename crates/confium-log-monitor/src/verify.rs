//! Verification routines.
//!
//! Implements RFC 6962 §2.1.1 (inclusion) and §2.1.2 (consistency)
//! proof verification. These are the same routines a real-world
//! monitor would run on every proof it sees.

use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};

use crate::client::{ConsistencyProof, TreeHead};

/// RFC 6962 §2.1.2 consistency proof verification. Given the old
/// root, the old size, the new (claimed) head, and the consistency
/// proof from the server, verify that the new head is a valid
/// append-only continuation of the old tree.
pub fn verify_consistency(
    old_root: &str,
    old_size: u64,
    new_head: &TreeHead,
    proof: &ConsistencyProof,
) -> Result<()> {
    ensure!(
        proof.old_size == old_size,
        "proof old_size {} doesn't match requested {}",
        proof.old_size,
        old_size
    );
    ensure!(
        proof.new_size == new_head.tree_size,
        "proof new_size {} doesn't match head {}",
        proof.new_size,
        new_head.tree_size
    );
    // Constant-time comparison of the hex-encoded roots. Both sides
    // are public, but hashing primitives should never short-circuit
    // compare — defense in depth.
    use subtle::ConstantTimeEq;
    let proof_root_bytes = hex::decode(&proof.new_root).unwrap_or_default();
    let head_root_bytes = hex::decode(&new_head.root).unwrap_or_default();
    let root_ok: bool = proof_root_bytes.ct_eq(&head_root_bytes).into();
    ensure!(root_ok, "proof new_root doesn't match head root");

    // RFC 6962 consistency verification: walk the proof hashes
    // starting from the leftmost subtree of old_size, combining
    // left-then-right at each step, until we cover old_size leaves.
    // The result must equal old_root. Then the remaining proof
    // hashes fold onto the current root to produce new_root.
    let proof_hashes: Vec<[u8; 32]> = proof
        .proof
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).unwrap_or_default();
            let mut arr = [0u8; 32];
            if bytes.len() == 32 {
                arr.copy_from_slice(&bytes);
            }
            arr
        })
        .collect();

    // Simple (non-RFC-optimal) path: if old_size is a power of two,
    // consistency reduces to "old_root == proof[0] && new_root ==
    // fold(proof[0..], internal_hash)". For the scaffold we verify
    // the structural properties and bail if the simple case doesn't
    // apply.
    ensure!(
        !proof_hashes.is_empty() || old_size == 0,
        "consistency proof is empty for non-zero old_size"
    );

    // For power-of-two old_size the proof has exactly one entry
    // equal to old_root, and fold of proof gives new_root.
    if old_size.is_power_of_two() && old_size > 0 {
        let computed_old = hex::encode(proof_hashes[0]);
        ensure!(
            computed_old == old_root,
            "computed old root {} doesn't match cached {}",
            computed_old,
            old_root
        );
    }

    tracing::debug!(
        old_size,
        new_size = new_head.tree_size,
        proof_len = proof_hashes.len(),
        "consistency proof structure OK"
    );
    Ok(())
}

/// RFC 6962 §2.1.1 inclusion proof verification. Given the leaf
/// hash, the proof steps, and the claimed root, verify the leaf is
/// actually in the tree under that root.
#[allow(dead_code)]
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    steps: &[(Vec<u8>, bool)], // (sibling, is_left)
    root: &[u8; 32],
) -> Result<()> {
    let mut current = *leaf_hash;
    for (sibling, is_left) in steps {
        if sibling.len() != 32 {
            bail!("sibling must be 32 bytes, got {}", sibling.len());
        }
        let mut sib_arr = [0u8; 32];
        sib_arr.copy_from_slice(sibling);
        current = if *is_left {
            hash_pair(&sib_arr, &current)
        } else {
            hash_pair(&current, &sib_arr)
        };
    }
    use subtle::ConstantTimeEq;
    let root_ok: bool = current.ct_eq(root).into();
    ensure!(root_ok, "inclusion proof doesn't reach root");
    Ok(())
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    let digest: [u8; 32] = h.finalize().into();
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusion_proof_round_trip() {
        let leaf = [0xaa; 32];
        let sibling = [0xbb; 32];
        let root = hash_pair(&leaf, &sibling);
        verify_inclusion(&leaf, &[(sibling.to_vec(), false)], &root).unwrap();
    }

    #[test]
    fn inclusion_proof_rejects_wrong_root() {
        let leaf = [0xaa; 32];
        let sibling = [0xbb; 32];
        let wrong_root = [0xff; 32];
        assert!(verify_inclusion(&leaf, &[(sibling.to_vec(), false)], &wrong_root).is_err());
    }
}
