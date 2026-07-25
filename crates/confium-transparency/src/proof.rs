//! Inclusion and consistency proofs.

use crate::merkle::Hash;

/// A Merkle inclusion proof: the list of sibling hashes needed to
/// reconstruct the root from a given leaf.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// Sequence number of the leaf being proven.
    pub sequence: u64,
    /// Sibling hashes from leaf level to root.
    pub siblings: Vec<Hash>,
}

/// A consistency proof: proves that an earlier tree state (with `from_size`
/// entries) is a prefix of the current tree state (with `to_size` entries).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsistencyProof {
    /// Earlier tree size.
    pub from_size: u64,
    /// Current tree size.
    pub to_size: u64,
    /// Path of hashes needed to verify consistency.
    pub path: Vec<Hash>,
}
