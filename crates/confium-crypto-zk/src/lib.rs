//! Zero-knowledge proof systems and set-membership primitives.
//!
//! # Audit status
//!
//! **Unaudited.** Fiat-Shamir transcripts carry rejection-sampled
//! challenges, but the crate has had no external cryptographic review.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod accumulator;
pub mod threshold_abs;
pub mod zk_set_membership;
pub mod zk_sig_possession;
