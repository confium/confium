//! Merkle tree state for the log server.
//!
//! Wraps `confium_transparency::MerkleTree` with persistence helpers
//! that rebuild the tree from the database on startup. After the
//! initial rebuild, the in-memory tree is the source of truth for
//! inclusion / consistency proofs; the database is the source of
//! truth for leaf entries.

use anyhow::{Context, Result};
use confium_transparency::{
    entry::{ArtifactType, MerkleEntry},
    merkle::{Hash, InclusionProof, MerkleError, MerkleTree},
};

use crate::db::Database;

pub struct MerkleState {
    pub tree: MerkleTree,
}

impl MerkleState {
    /// Rebuild the Merkle tree from every entry in the database.
    /// O(N) on startup; subsequent appends are O(log N).
    ///
    /// Leaf hashes cover the entry's sequence, timestamp, and
    /// artifact hash, so the rebuild reuses the *stored* timestamps
    /// — freshly stamped ones would silently change every leaf and
    /// invalidate every proof issued before the restart.
    pub fn from_db(db: &Database) -> Result<Self> {
        let rows = db
            .all_entries_for_rebuild()
            .context("loading entries for rebuild")?;
        let mut tree = MerkleTree::new();
        for row in rows {
            let entry = MerkleEntry {
                sequence: row.sequence,
                timestamp: row.timestamp,
                artifact_type: row.artifact_type,
                artifact_hash: row.artifact_hash,
                metadata: serde_json::Value::Null,
            };
            tree.append(entry);
        }
        tracing::info!(count = tree.len(), "rebuilt Merkle tree");
        Ok(MerkleState { tree })
    }

    /// Append one leaf. The timestamp must be the same one stored in
    /// the database for this entry — the two must never diverge or
    /// a later rebuild produces a different tree.
    pub fn append(
        &mut self,
        leaf: Hash,
        artifact_type: ArtifactType,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> u64 {
        let entry = MerkleEntry {
            sequence: 0,
            timestamp,
            artifact_type,
            artifact_hash: leaf,
            metadata: serde_json::Value::Null,
        };
        self.tree.append(entry)
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    pub fn len(&self) -> u64 {
        self.tree.len() as u64
    }

    pub fn inclusion_proof(
        &self,
        sequence: u64,
    ) -> std::result::Result<InclusionProof, MerkleError> {
        self.tree.inclusion_proof(sequence)
    }

    pub fn consistency_proof(&self, old_size: u64) -> std::result::Result<Vec<Hash>, MerkleError> {
        self.tree.consistency_proof(old_size as usize)
    }
}
