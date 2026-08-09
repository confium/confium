//! Key lifecycle, HSM protection, and production hardening for threshold keys.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0
#![allow(dead_code)] // Key-lifecycle structs are pub API for upcoming HSM/KMS work

pub mod hsm_protection;
pub mod integrity;
pub mod key_mgmt_and_protocols;
pub mod production_hardening;
pub mod stealth_address;
pub mod threshold_bip32;
