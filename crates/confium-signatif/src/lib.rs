//! # confium-signatif
//!
//! Implementation of the SIGNATIF framework — Sealed Interoperable
//! Graduated Non-repudiable Anchored Trust Infrastructure Framework
//! (ISO/TC 154 working draft) — on top of the Confium cryptographic
//! substrate.
//!
//! SIGNATIF is the framework, Confium is the implementation tool, and a
//! domain scheme (for example CNML for metrology) adopts the framework
//! through this crate:
//!
//! - [`graph`]: the trust graph (delegation DAG) and path-finding that
//!   collects every valid verification path.
//! - [`bundle`]: versioned, signed trust anchor bundles.
//! - [`scope`]: the multi-dimensional scope lattice with monotonic
//!   narrowing.
//! - [`artifact`]: trusted artifacts with dimension-tagged co-signature
//!   blocks over one canonical payload hash.
//! - [`pipeline`]: the ordered hard/soft check verification pipeline,
//!   [`coverage`] reports, classification and acceptance policies.
//! - [`revocation`]: signed CRLs, hash bindings, transitive propagation.
//! - [`ceremony`]: verifiable ceremony transcripts and their audit.
//! - [`registry`]: the five scheme-maintained registries.
//!
//! All verification is offline-capable against a trust anchor bundle.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artifact;
pub mod bundle;
pub mod ceremony;
pub mod coverage;
pub mod discovery;
pub mod error;
pub mod graph;
pub mod jcs;
pub mod multilog;
pub mod passport;
pub mod pipeline;
pub mod registry;
pub mod revocation;
pub mod scope;
pub mod time;

pub use error::{SignatifError, SignatifResult};
