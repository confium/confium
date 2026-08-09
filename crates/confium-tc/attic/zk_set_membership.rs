//! Zero-knowledge set membership proof.
//!
//! Proves that a committed value belongs to a set, WITHOUT revealing
//! which element it is. Uses a Merkle tree: the prover shows they
//! know an inclusion proof for some element in the set.

use sha2::{Digest, Sha256};

/// A ZK set membership proof.
#[derive(Debug, Clone)]
pub struct SetMembershipProof {
    /// The element (hidden, random-encoded).
    pub element_commitment: [u8; 32],
    /// Merkle inclusion proof for the element.
    pub merkle_proof: Vec<MerkleStep>,
    /// The root of the set's Merkle tree.
    pub root: [u8; 32],
}

/// One step in a Merkle proof.
#[derive(Debug, Clone)]
pub struct MerkleStep {
    pub sibling: [u8; 32],
    pub direction: Direction,
}

/// Direction of a Merkle proof step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

/// Build a Merkle tree from a set of elements.
pub fn build_merkle_tree(elements: &[Vec<u8>]) -> (Vec<[u8; 32]>, [u8; 32]) {
    if elements.is_empty() {
        return (vec![], [0u8; 32]);
    }
    let mut leaves: Vec<[u8; 32]> = elements
        .iter()
        .map(|e| {
            let mut h = Sha256::new();
            h.update(b"leaf:");
            h.update(e);
            let result = h.finalize();
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&result);
            leaf
        })
        .collect();

    let root = compute_root(&leaves);
    (leaves, root)
}

fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(chunk[0]);
            }
        }
        level = next;
    }
    level[0]
}

fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"node:");
    h.update(a);
    h.update(b);
    let result = h.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn leaf_hash(element: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"leaf:");
    h.update(element);
    let result = h.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Generate an inclusion proof for `element` at `index` in the set.
pub fn generate_proof(elements: &[Vec<u8>], index: usize) -> Option<SetMembershipProof> {
    if index >= elements.len() {
        return None;
    }
    let (leaves, root) = build_merkle_tree(elements);
    let element = &elements[index];

    let commitment = leaf_hash(element);

    let merkle_proof = build_proof(&leaves, index);

    Some(SetMembershipProof {
        element_commitment: commitment,
        merkle_proof,
        root,
    })
}

fn build_proof(leaves: &[[u8; 32]], index: usize) -> Vec<MerkleStep> {
    let mut proof = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() {
            proof.push(MerkleStep {
                sibling: level[sibling_idx],
                direction: if idx % 2 == 0 { Direction::Right } else { Direction::Left },
            });
        }
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(chunk[0]);
            }
        }
        level = next;
        idx /= 2;
    }
    proof
}

/// Verify a set membership proof.
pub fn verify_proof(proof: &SetMembershipProof, element: &[u8]) -> bool {
    let commitment = leaf_hash(element);
    if commitment != proof.element_commitment {
        return false;
    }

    let mut current = commitment;
    for step in &proof.merkle_proof {
        current = match step.direction {
            Direction::Left => hash_pair(&step.sibling, &current),
            Direction::Right => hash_pair(&current, &step.sibling),
        };
    }
    current == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_has_zero_root() {
        let (_, root) = build_merkle_tree(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn single_element_proof() {
        let elements = vec![b"a".to_vec()];
        let proof = generate_proof(&elements, 0).unwrap();
        assert!(verify_proof(&proof, b"a"));
    }

    #[test]
    fn wrong_element_rejected() {
        let elements = vec![b"a".to_vec(), b"b".to_vec()];
        let proof = generate_proof(&elements, 0).unwrap();
        assert!(!verify_proof(&proof, b"b"));
    }

    #[test]
    fn proof_for_each_element() {
        let elements: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8]).collect();
        for i in 0..elements.len() {
            let proof = generate_proof(&elements, i).unwrap();
            assert!(verify_proof(&proof, &elements[i]), "element {i}");
        }
    }

    #[test]
    fn different_sets_different_roots() {
        let (_, root1) = build_merkle_tree(&[b"a".to_vec()]);
        let (_, root2) = build_merkle_tree(&[b"b".to_vec()]);
        assert_ne!(root1, root2);
    }

    #[test]
    fn out_of_bounds_returns_none() {
        let elements = vec![b"a".to_vec()];
        assert!(generate_proof(&elements, 5).is_none());
    }

    #[test]
    fn merkle_proof_steps_correct() {
        let elements: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8]).collect();
        let proof = generate_proof(&elements, 1).unwrap();
        // 4 elements → 2 levels → 2 proof steps
        assert_eq!(proof.merkle_proof.len(), 2);
    }

    #[test]
    fn power_of_two_tree() {
        let elements: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8]).collect();
        let proof = generate_proof(&elements, 3).unwrap();
        assert!(verify_proof(&proof, &elements[3]));
    }

    #[test]
    fn non_power_of_two() {
        let elements: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8]).collect();
        let proof = generate_proof(&elements, 4).unwrap();
        assert!(verify_proof(&proof, &elements[4]));
    }
}
