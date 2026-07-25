//! Escrow metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metadata about an escrowed key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowMetadata {
    /// When the key was escrowed.
    pub escrowed_at: DateTime<Utc>,
    /// Who escrowed it (actor ID).
    pub escrowed_by: String,
    /// Identifier for the escrowed key.
    pub key_id: String,
    /// Type of key (e.g., "Ed25519", "ECDSA-P256", "OpenPGP-private-key").
    pub key_type: String,
    /// Number of custodians holding shares (N).
    pub custodian_count: u32,
    /// Threshold T required for recovery.
    pub threshold: u32,
    /// Optional: human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

impl EscrowMetadata {
    /// Construct new metadata with current timestamp.
    pub fn new(
        escrowed_by: impl Into<String>,
        key_id: impl Into<String>,
        key_type: impl Into<String>,
        custodian_count: u32,
        threshold: u32,
    ) -> Self {
        Self {
            escrowed_at: Utc::now(),
            escrowed_by: escrowed_by.into(),
            key_id: key_id.into(),
            key_type: key_type.into(),
            custodian_count,
            threshold,
            description: None,
        }
    }
}
