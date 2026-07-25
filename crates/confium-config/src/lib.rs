//! Deployment manifest schema and validation for the Confium framework.
//!
//! A Confium deployment is described by a signed deployment manifest
//! (`confium.toml`). This crate provides the schema, parser, validator,
//! and serialization.
//!
//! See `TODO.roadmap/33-config-manifest.md` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod manifest;
mod mode;
mod validate;

pub use manifest::*;
pub use mode::*;
pub use validate::*;
