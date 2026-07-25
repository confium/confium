//! Hardware token descriptors.
//!
//! Describes where a key lives in hardware. Standards-only — no vendor
//! SDKs. Covers YubiKey PIV, YubiKey OpenPGP applet, OpenPGP card v3+,
//! TPM 2.0.

use serde::{Deserialize, Serialize};

/// A hardware token holding one or more keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HardwareToken {
    /// YubiKey PIV applet (PKCS#11 interface).
    YubiKeyPiv {
        /// PIV slot identifier (e.g., "9a", "9c", "9e").
        slot: String,
        /// PIN policy.
        pin_policy: PinPolicy,
    },
    /// YubiKey OpenPGP applet (OpenPGP card interface).
    YubiKeyOpenpgp {
        /// OpenPGP key slot (sig, dec, aut).
        slot: OpenpgpSlot,
    },
    /// Any OpenPGP card v3+ device (YubiKey, Nitrokey, Gnuk).
    OpenpgpCard {
        /// Card identifier (typically derived from serial number).
        card_id: String,
        /// OpenPGP key slot.
        slot: OpenpgpSlot,
    },
    /// TPM 2.0 sealed key.
    Tpm {
        /// TPM persistent handle (e.g., 0x81000001).
        handle: u32,
    },
}

/// PIN entry policy for PIV signing.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinPolicy {
    /// PIN never required (default).
    #[default]
    Never,
    /// PIN required once per session.
    Once,
    /// PIN required every sign operation.
    Always,
}

/// OpenPGP card key slot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenpgpSlot {
    /// Signature slot (SIG).
    Signature,
    /// Decryption slot (DEC).
    Decryption,
    /// Authentication slot (AUT).
    Authentication,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yubikey_piv_serializes() {
        let t = HardwareToken::YubiKeyPiv {
            slot: "9c".into(),
            pin_policy: PinPolicy::Always,
        };
        let json = serde_json::to_string(&t).unwrap();
        let recovered: HardwareToken = serde_json::from_str(&json).unwrap();
        match recovered {
            HardwareToken::YubiKeyPiv {
                slot,
                pin_policy: _,
            } => assert_eq!(slot, "9c"),
            _ => panic!("wrong variant"),
        }
    }
}
