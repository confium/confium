//! OpenPGP card slot identifiers.

use serde::{Deserialize, Serialize};

/// OpenPGP card slot (per OpenPGP card spec v3.x).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenpgpSlot {
    /// Signature (SIG) slot — key for signing documents.
    Signature,
    /// Decryption (DEC) slot — key for decrypting messages.
    Decryption,
    /// Authentication (AUT) slot — key for non-repudiation / SSH auth.
    Authentication,
}

/// PIN policy supported by the OpenPGP card spec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinPolicy {
    /// PIN never required.
    #[default]
    Never,
    /// PIN required once per session.
    Once,
    /// PIN required every operation.
    Always,
}

/// PIN reference identifiers per OpenPGP card spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinReference {
    /// User PIN (PW1).
    UserPin,
    /// Resetting Code (RC).
    ResettingCode,
    /// Admin PIN (PW3).
    AdminPin,
}
