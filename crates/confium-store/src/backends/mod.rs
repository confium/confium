//! In-tree keystore backends.
//!
//! Each backend is a module that implements
//! [`crate::backend::StoreBackend`] and registers itself at link time
//! via [`crate::register_backend!`]. The `memory` backend ships today;
//! `filesystem` is stubbed pending the keyfmt integration.

pub mod filesystem;
pub mod memory;
