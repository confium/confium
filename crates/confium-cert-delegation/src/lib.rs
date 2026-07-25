//! Scoped certificate delegation templates.
//!
//! When a parent cert delegates bounded authority to a child cert, the
//! child can issue/sign artifacts only within the delegated scope. This
//! crate provides the scope types and validation logic.
//!
//! Example: OIML CNML Manufacturer Model Cert delegates to manufacturer
//! the right to issue Instance Certs for a specific instrument model only.
//!
//! See `TODO.roadmap/32-cert-delegation-cms-xmldsig.md` for the full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod constraint;
mod operation;
mod scope;
mod validate;

pub use constraint::*;
pub use operation::*;
pub use scope::*;
pub use validate::*;
