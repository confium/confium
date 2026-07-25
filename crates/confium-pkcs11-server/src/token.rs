//! PKCS#11 token model.

use crate::slot::SlotId;
use serde::{Deserialize, Serialize};

/// Token info (per PKCS#11 `CK_TOKEN_INFO`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Slot this token is in.
    pub slot: SlotId,
    /// Token label (32 bytes in real PKCS#11).
    pub label: String,
    /// Threshold quorum size.
    pub threshold: u32,
    /// Total parties N.
    pub num_parties: u32,
    /// Signing algorithm.
    pub signing_algorithm: String,
    /// Quorum coordinator URL.
    pub coordinator: String,
}

impl TokenInfo {
    /// Construct for a Confium-backed quorum.
    pub fn for_quorum(
        slot: SlotId,
        quorum_id: &str,
        threshold: u32,
        num_parties: u32,
        signing_algorithm: &str,
        coordinator: &str,
    ) -> Self {
        Self {
            slot,
            label: format!("Confium/{quorum_id}"),
            threshold,
            num_parties,
            signing_algorithm: signing_algorithm.into(),
            coordinator: coordinator.into(),
        }
    }
}
