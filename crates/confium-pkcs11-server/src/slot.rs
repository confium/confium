//! PKCS#11 slot model.

use serde::{Deserialize, Serialize};

/// A PKCS#11 slot identifier. Maps 1:1 to a Confium quorum.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SlotId(pub u64);

/// Slot info (per PKCS#11 `CK_SLOT_INFO`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    /// Slot description (32 bytes in real PKCS#11, here as String).
    pub description: String,
    /// Hardware manufacturer ID.
    pub manufacturer: String,
    /// True if a token is present.
    pub token_present: bool,
    /// True if hardware (vs software slot).
    pub hardware: bool,
    /// Associated quorum ID.
    pub quorum_id: String,
}

impl SlotInfo {
    /// Construct slot info for a Confium quorum.
    pub fn for_quorum(quorum_id: impl Into<String>) -> Self {
        let qid = quorum_id.into();
        Self {
            description: format!("Confium quorum: {qid}"),
            manufacturer: "Confium Project".into(),
            token_present: true,
            hardware: false,
            quorum_id: qid,
        }
    }
}
