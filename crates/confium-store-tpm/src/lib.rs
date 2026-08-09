//! Confium Store TPM 2.0 backend.
//!
//! Hardware-backed keystore for Confium that targets the platform TPM 2.0
//! available on every modern Linux/Windows machine. Wraps the
//! [`tss-esapi`](https://docs.rs/tss-esapi) Rust binding for the TPM 2.0
//! TSS2 Enhanced System API.
//!
//! This crate is a *backend* for [`confium-store`]: it implements the
//! [`StoreBackend`](confium_store::backend::StoreBackend) trait and
//! registers itself at link time via
//! [`register_backend!`](confium_store::register_backend!). Drop-in with
//! the in-memory and filesystem backends — same Rust API, different
//! storage medium.
//!
//! ## Status
//!
//! **Skeleton.** The trait wiring, configuration model, and hierarchy
//! type are in place; the storage operations return
//! [`NotImplemented`](confium_store::Error::NotImplemented). The
//! `tss-esapi` integration lands in the next revision behind the `tpm`
//! feature flag. See `TODO.roadmap/18-hardware-keystore-backends.md`.
//!
//! ## Configuration
//!
//! The backend reads its configuration from the
//! [`Options`](confium_store::backend::Options) map passed to
//! [`StoreBackend::open`](confium_store::backend::StoreBackend::open):
//!
//! | key              | meaning                                             | default            |
//! |------------------|-----------------------------------------------------|--------------------|
//! | `tpm_device`     | path to the TPM device (e.g. `/dev/tpmrmis0`)       | auto-detect        |
//! | `hierarchy`      | `owner` / `platform` / `endorsement`                | `owner`            |
//! | `parent_handle`  | persistent parent key handle (hex, e.g. `0x81000001`) | required at runtime |
//! | `parent_password` | authorisation value for the parent key             | empty              |
//!
//! ## Example
//!
//! ```ignore
//! // Marked `ignore` because the doctest compilation triggers a Cargo
//! // workspace feature-unification issue (E0460) when run via
//! // `cargo test --workspace`. The code is correct; run individually
//! // with `cargo test -p confium-store-tpm --doc` to verify.
//! use confium_store::backend::{Options, StoreBackend};
//! use confium_store_tpm::TpmBackend;
//!
//! let backend = TpmBackend;
//! let mut opts = Options::new();
//! opts.insert("tpm_device".into(), "/dev/tpmrmis0".into());
//! opts.insert("hierarchy".into(), "owner".into());
//! let store = backend.open(&opts).expect("open tpm backend");
//! ```

// FFI entry points (none yet) would accept raw pointers and null-check
// them before dereferencing; mirroring the convention from
// `confium-store`.
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

pub mod backend;
pub mod config;

pub use backend::{TpmBackend, TpmInstance};
pub use config::{Hierarchy, ParentHandle, TpmConfig};
