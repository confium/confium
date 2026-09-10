//! Zero-knowledge proof systems and set-membership primitives.
//!
//! # Audit status
//!
//! **Unaudited.** Fiat-Shamir transcripts carry rejection-sampled
//! challenges, but the crate has had no external cryptographic review.

#![forbid(unsafe_code)]

pub mod accumulator;
pub mod threshold_abs;
/// Experimental demonstration primitive — NOT AUDITED. The proof
pub mod zk_key_possession;
pub mod zk_set_membership;

/// UNAUDITED: proving possession of an ECDSA *signature* without
/// revealing it requires proving the coordinate check `x(R) ≡ r
/// (mod n)` — a bit-decomposition relation no plain sigma-protocol
/// carries; it needs a circuit-based (or Camenisch-style) construction.
/// The
/// transcript commits to the ECDSA `s` component, which a verifier
/// cannot reconstruct without the signature itself; the shipped
/// `verify_possession` is a placeholder that accepts any non-zero
/// response. Do not use. Compiled only behind the
/// `unaudited-experimental` feature.
#[cfg(feature = "unaudited-experimental")]
pub mod zk_sig_possession;
