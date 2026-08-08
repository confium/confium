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
    /// Rebuild the Merkle tree from every leaf hash in the database.
    /// O(N) on startup; subsequent appends are O(log N).
    pub fn from_db(db: &Database) -> Result<Self> {
        let leaves = db.all_leaf_hashes().context("loading leaf hashes")?;
        let mut tree = MerkleTree::new();
        for leaf in leaves {
            let entry = MerkleEntry::new(0, ArtifactType::CertificateIssuance, leaf);
            tree.append(entry);
        }
        tracing::info!(count = tree.len(), "rebuilt Merkle tree");
        Ok(MerkleState { tree })
    }

    pub fn append(&mut self, leaf: Hash) -> u64 {
        let entry = MerkleEntry::new(0, ArtifactType::CertificateIssuance, leaf);
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
