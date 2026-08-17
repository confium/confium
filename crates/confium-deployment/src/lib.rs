//! Deployment manifest + actor identity management for Confium.
//!
//! A Confium deployment is described by a signed deployment manifest
//! (`confium.toml`). This crate provides:
//!
//! - The manifest schema, parser, validator, and serializer
//! - Actor identity types (manufacturer, lab, IA, BIML director) and storage
//! - Hardware token descriptors (YubiKey, OpenPGP card, TPM)
//! - Signer attributes for predicate-based signing
//!
//! See `TODO.roadmap/33-config-manifest.md` and
//! `TODO.roadmap/34-identity-and-hardware.md` for full specs.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod identity;
pub mod manifest;
pub mod mode;
pub mod signatif;
pub mod validate;

pub use manifest::*;
pub use validate::*;
