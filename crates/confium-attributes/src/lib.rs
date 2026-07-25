//! Attribute-based threshold party selection.
//!
//! Allows deployments to express predicates like:
//! - "at least K signers have attribute X"
//! - "at least K distinct values of attribute X"
//! - "no signer has attribute Y"
//! - "all signers have attribute Z"
//!
//! Predicates compose via boolean AND/OR/NOT.
//!
//! See `TODO.roadmap/38-attribute-based-threshold.md` for the full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![recursion_limit = "256"]

mod ast;
mod dsl;
mod evaluate;

pub use ast::*;
pub use dsl::*;
pub use evaluate::*;
