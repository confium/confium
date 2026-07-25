//! OTS proof types.

use serde::{Deserialize, Serialize};

/// An OpenTimestamps proof (compact form).
///
/// In real OTS format, this is a sequence of attestation operations.
/// Here we model it semantically; serialization to .ots file format
/// is a separate concern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtsProof {
    /// Original hash that was stamped.
    pub hash: [u8; 32],
    /// Bitcoin block height where the attestation anchor was mined.
    pub bitcoin_height: u32,
    /// Merkle branch from the hash to the block's Merkle root (if direct anchor).
    pub merkle_branch: Vec<[u8; 32]>,
    /// The Bitcoin block's Merkle root.
    pub merkle_root: [u8; 32],
    /// Calendar server that facilitated the stamping (if applicable).
    #[serde(default)]
    pub calendar_server: Option<String>,
}

impl OtsProof {
    /// Construct a new proof.
    pub fn new(hash: [u8; 32], bitcoin_height: u32) -> Self {
        Self {
            hash,
            bitcoin_height,
            merkle_branch: Vec::new(),
            merkle_root: [0u8; 32],
            calendar_server: None,
        }
    }
}

/// Verification result.
#[derive(Debug, Clone)]
pub struct OtsVerification {
    /// Whether the proof is valid.
    pub valid: bool,
    /// Bitcoin block height anchoring the proof.
    pub bitcoin_height: u32,
    /// Approximate timestamp (from Bitcoin block header).
    pub block_timestamp: Option<u64>,
}

/// Errors during OTS operations.
#[derive(Debug, thiserror::Error)]
pub enum OtsError {
    /// Calendar server unreachable.
    #[error("calendar server unreachable: {0}")]
    CalendarUnreachable(String),
    /// Proof invalid.
    #[error("proof invalid: {0}")]
    InvalidProof(String),
    /// Bitcoin backend unavailable.
    #[error("Bitcoin backend unavailable: {0}")]
    BitcoinBackend(String),
}
