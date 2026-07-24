//! Confium Store: compartmentalized key/secret persistence.
//!
//! Two compartments per `(module_id, app_id)` pair:
//!
//! - **Public** — distributed, identity-indexed, signed
//! - **Private** — per-device, key-id-indexed, optionally hardware-backed
//!
//! Backends planned: `filesystem`, `memory`, `pkcs11`, `tpm`, `cloud-kms`.
//!
//! Today this is a placeholder skeleton. See `TODO.finalize/12-keystore-interface.md`
//! for the FFI design and `TODO.roadmap/01-architecture-overview.md` for the
//! pillar context.
