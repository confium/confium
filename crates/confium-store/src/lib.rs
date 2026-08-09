//! Confium Store: compartmentalized key/secret persistence.
//!
//! Two compartments per `(module_id, app_id)` pair:
//!
//! - **Public** — distributed, identity-indexed, signed
//! - **Private** — per-device, key-id-indexed, optionally hardware-backed
//!
//! Backends ship in-tree and register at link time via
//! [`register_backend!`]:
//!
//! - `memory` — in-process HashMap (dev / test)
//! - `filesystem` — RFC 9580 keyring files (stub, pending `keyfmt`)
//! - `pkcs11`, `tpm`, `cloud-kms` — future, separate plugin repos
//!
//! See `TODO.finalize/12-keystore-interface.md` for the FFI design and
//! `TODO.roadmap/01-architecture-overview.md` for the pillar context.

// FFI entry points accept raw pointers and null-check them before
// dereferencing; they are not `unsafe` from the C caller's perspective.
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

pub mod backend;
pub mod backends;
pub mod error;
pub mod ffi;
pub mod identity;
pub mod keystore;

pub use backend::{Compartment, Options, StoreBackend, StoreInstance};
pub use error::{Error, ErrorCode, Result};
pub use identity::Identity;
pub use keystore::Keystore;
