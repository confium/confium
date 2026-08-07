//! Witness gossip protocol for transparency log monitoring.
//!
//! Third-party witnesses track tree heads (STHs) and gossip them
//! between each other to detect split-view attacks. A malicious log
//! that presents different views to different clients will be caught
//! when witnesses compare notes.
//!
//! ## Protocol
//!
//! 1. Witness fetches the latest tree head from the log
//! 2. Witness verifies consistency with its previous head
//! 3. Witness gossips the new head to peer witnesses
//! 4. Peer witnesses verify and store the head

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::merkle::{Hash, MerkleTree};

/// A signed tree head (STH) — the log's commitment to its state at
/// a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TreeHead {
    /// Number of entries in the tree.
    pub tree_size: u64,
    /// Root hash.
    pub root_hash: Hash,
    /// Timestamp when this head was produced.
    pub timestamp: DateTime<Utc>,
}

/// A witness that monitors a transparency log.
///
/// Stores all known tree heads and verifies consistency between
/// successive heads. Heads that fail consistency are rejected.
#[derive(Debug, Default)]
pub struct Witness {
    /// Known heads indexed by tree_size.
    heads: HashMap<u64, TreeHead>,
    /// Witness identity.
    pub witness_id: String,
}

/// Errors during witness operations.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// Consistency proof verification failed.
    #[error("consistency proof failed: expected {expected:?}, got {actual:?}")]
    ConsistencyFailed {
        /// Expected root hash.
        expected: Hash,
        /// Actual root hash.
        actual: Hash,
    },
    /// Old head not found for consistency check.
    #[error("old tree head (size {0}) not known")]
    OldHeadUnknown(u64),
}

impl Witness {
    /// Create a new witness with the given identity.
    pub fn new(witness_id: &str) -> Self {
        Self {
            heads: HashMap::new(),
            witness_id: witness_id.into(),
        }
    }

    /// Receive a new tree head. If the witness already knows a head
    /// at a smaller tree size, `consistency_proof` must be provided
    /// to verify the transition.
    ///
    /// `tree` is the current tree state (used to brute-force verify
    /// consistency via root recomputation).
    pub fn receive_head(
        &mut self,
        head: TreeHead,
        tree: &MerkleTree,
    ) -> Result<(), WitnessError> {
        if let Some(old) = self.latest_head() {
            if head.tree_size > old.tree_size {
                tree.verify_consistency(
                    old.root_hash,
                    head.root_hash,
                    old.tree_size as usize,
                    head.tree_size as usize,
                    &[],
                )
                .map_err(|_| WitnessError::ConsistencyFailed {
                    expected: head.root_hash,
                    actual: tree.root(),
                })?;
            }
        }
        self.heads.insert(head.tree_size, head);
        Ok(())
    }

    /// Get the latest known head (largest tree_size).
    pub fn latest_head(&self) -> Option<&TreeHead> {
        self.heads.values().max_by_key(|h| h.tree_size)
    }

    /// Get all known heads sorted by tree_size.
    pub fn known_heads(&self) -> Vec<&TreeHead> {
        let mut heads: Vec<&TreeHead> = self.heads.values().collect();
        heads.sort_by_key(|h| h.tree_size);
        heads
    }

    /// Get a specific head by tree_size.
    pub fn head_at(&self, tree_size: u64) -> Option<&TreeHead> {
        self.heads.get(&tree_size)
    }

    /// Number of known heads.
    pub fn head_count(&self) -> usize {
        self.heads.len()
    }

    /// Gossip a head to another witness. The peer verifies and
    /// stores the head.
    pub fn gossip_to(
        &self,
        peer: &mut Witness,
        tree_size: u64,
        tree: &MerkleTree,
    ) -> Result<(), WitnessError> {
        let head = self
            .heads
            .get(&tree_size)
            .ok_or(WitnessError::OldHeadUnknown(tree_size))?;
        peer.receive_head(head.clone(), tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{ArtifactType, MerkleEntry};

    fn build_tree(n: u64) -> MerkleTree {
        let mut tree = MerkleTree::new();
        for i in 0..n {
            tree.append(MerkleEntry::new(i, ArtifactType::ThresholdSignature, [i as u8; 32]));
        }
        tree
    }

    #[test]
    fn witness_starts_empty() {
        let w = Witness::new("w1");
        assert_eq!(w.head_count(), 0);
        assert!(w.latest_head().is_none());
    }

    #[test]
    fn receive_first_head() {
        let tree = build_tree(5);
        let mut w = Witness::new("w1");
        let head = TreeHead {
            tree_size: 5,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w.receive_head(head, &tree).unwrap();
        assert_eq!(w.head_count(), 1);
        assert_eq!(w.latest_head().unwrap().tree_size, 5);
    }

    #[test]
    fn receive_consistent_head() {
        let mut tree = build_tree(5);
        let mut w = Witness::new("w1");

        let head1 = TreeHead {
            tree_size: 5,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w.receive_head(head1, &tree).unwrap();

        tree.append(MerkleEntry::new(5, ArtifactType::ThresholdSignature, [5; 32]));
        let head2 = TreeHead {
            tree_size: 6,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w.receive_head(head2, &tree).unwrap();
        assert_eq!(w.head_count(), 2);
        assert_eq!(w.latest_head().unwrap().tree_size, 6);
    }

    #[test]
    fn reject_inconsistent_head() {
        let tree = build_tree(5);
        let mut w = Witness::new("w1");
        let head1 = TreeHead {
            tree_size: 5,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w.receive_head(head1, &tree).unwrap();

        let fake_root = [0xFF; 32];
        let head2 = TreeHead {
            tree_size: 10,
            root_hash: fake_root,
            timestamp: Utc::now(),
        };
        let result = w.receive_head(head2, &tree);
        assert!(result.is_err());
    }

    #[test]
    fn known_heads_sorted_by_size() {
        let mut tree = build_tree(1);
        let mut w = Witness::new("w1");

        let head1 = TreeHead {
            tree_size: 1,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w.receive_head(head1, &tree).unwrap();

        tree.append(MerkleEntry::new(1, ArtifactType::ThresholdSignature, [1; 32]));
        let head2 = TreeHead {
            tree_size: 2,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w.receive_head(head2, &tree).unwrap();

        tree.append(MerkleEntry::new(2, ArtifactType::ThresholdSignature, [2; 32]));
        let head3 = TreeHead {
            tree_size: 3,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w.receive_head(head3, &tree).unwrap();

        let heads = w.known_heads();
        assert_eq!(heads.len(), 3);
        assert_eq!(heads[0].tree_size, 1);
        assert_eq!(heads[1].tree_size, 2);
        assert_eq!(heads[2].tree_size, 3);
    }

    #[test]
    fn gossip_to_peer() {
        let tree = build_tree(5);
        let mut w1 = Witness::new("w1");
        let mut w2 = Witness::new("w2");

        let head = TreeHead {
            tree_size: 5,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w1.receive_head(head, &tree).unwrap();
        w1.gossip_to(&mut w2, 5, &tree).unwrap();
        assert_eq!(w2.head_count(), 1);
        assert_eq!(w2.head_at(5).unwrap().root_hash, tree.root());
    }

    #[test]
    fn gossip_unknown_head_errors() {
        let tree = build_tree(5);
        let w1 = Witness::new("w1");
        let mut w2 = Witness::new("w2");
        assert!(w1.gossip_to(&mut w2, 99, &tree).is_err());
    }

    #[test]
    fn head_at_returns_correct_head() {
        let tree = build_tree(5);
        let mut w = Witness::new("w1");
        let head = TreeHead {
            tree_size: 5,
            root_hash: tree.root(),
            timestamp: Utc::now(),
        };
        w.receive_head(head, &tree).unwrap();
        assert!(w.head_at(5).is_some());
        assert!(w.head_at(3).is_none());
    }
}
