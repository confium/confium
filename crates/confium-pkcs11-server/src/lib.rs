//! PKCS#11 v3.0 server dispatching to Confium threshold protocol.
//!
//! This is the Mode 2 cornerstone. Exposes PKCS#11 v3.0 API (`C_Sign`,
//! `C_Decrypt`, `C_GenerateKeyPair`, etc.) and internally dispatches
//! to threshold protocol. Existing PKCS#11 consumers (OpenSSL, OpenSSH,
//! Java KeyStore, nginx, Apache) work unchanged.
//!
//! The full PKCS#11 v3.0 surface is ~40+ functions. This crate provides
//! the dispatch layer that routes calls to a quorum coordinator; the
//! real PKCS#11 FFI shim is generated separately.
//!
//! See `TODO.roadmap/28-mode2-pki-replacement.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod dispatch;
pub mod slot;
pub mod token;

pub use dispatch::*;
pub use slot::*;
pub use token::*;
