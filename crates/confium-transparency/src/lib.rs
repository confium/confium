//! Transparency log + OpenTimestamps + Evidence Records for Confium.
//!
//! Three layers of artifact provenance over time:
//!
//! - **Merkle tree transparency log**: every artifact (cert, signature,
//!   revocation, re-share event) is appended. Tree roots periodically
//!   anchored to Bitcoin via OpenTimestamps. Verifiers can prove any
//!   artifact was in the publicly-visible tree as of a given Bitcoin block.
//! - **OpenTimestamps (OTS)**: anchors hashes to Bitcoin blockchain via
//!   public calendar servers.
//! - **Evidence Records (RFC 4998 ERS)**: long-term archival protection
//!   via periodic re-timestamping as hash algorithms age.
//!
//! See `TODO.roadmap/36-transparency-and-ots.md` and
//! `TODO.roadmap/37-long-term-archival.md` for full specs.
//!
//! # Example
//!
//! ```
//! use confium_transparency::{MerkleTree, entry::{ArtifactType, MerkleEntry}};
//!
//! let mut tree = MerkleTree::new();
//! let hash = [0u8; 32]; // sha256 of your artifact
//! let entry = MerkleEntry::new(0, ArtifactType::CertificateIssuance, hash);
//! let seq = tree.append(entry);
//! let root = tree.root();
//! let proof = tree.inclusion_proof(seq)?;
//! let entry_ref = tree.entry(seq)?;
//! MerkleTree::verify_inclusion(entry_ref, &proof, root)?;
//! # Ok::<(), confium_transparency::MerkleError>(())
//! ```

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod entry;
pub mod ers;
pub mod merkle;
pub mod ots;
pub mod proof;
pub mod witness;

#[cfg(test)]
mod props;

pub use entry::*;
pub use merkle::*;
pub use proof::*;
