//! Public Rust API and plugin SDK for Confium.
//!
//! This crate is the bottom of the dependency stack. Everyone (core, store,
//! registry, net, tc, plugin authors) can depend on it. It does **not**
//! include the plugin loader itself.
//!
//! Today this is a placeholder skeleton. Eventually it will hold:
//! - shared FFI types (opaque handles, error codes, options)
//! - traits that plugin authors implement
//! - the `#[plugin_interface]` proc-macro re-export
//! - documentation entry point
//!
//! See `TODO.roadmap/02-workspace-layout.md` for the full crate map and
//! `TODO.roadmap/03-plugin-contract.md` for the contract this crate will
//! expose.
