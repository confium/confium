//! CMP20 threshold ECDSA over P-256 (Canetti, Makriyannis, Peled 2020,
//! eprint 2020/496).
//!
//! A newer, more efficient threshold ECDSA protocol than GG18. Key
//! improvements exploited here:
//!
//! - **Non-interactive key generation** — DKG collapses to a single
//!   broadcast round (each party commits its public share; no per-peer
//!   share exchange is needed in the simplified path).
//! - **Three-round signing** — down from GG18's four. Round 1 commits
//!   nonces, round 2 reveals them and carries the MtA products, round 3
//!   posts partial signatures and combines in the same round.
//! - **Identifiable abort** — when a partial signature fails to verify
//!   the offending party is reported by index rather than failing
//!   opaquely.
//!
//! Wired as a [`confium_tc::registry::TcScheme`] plugin with two scheme
//! names registered through [`confium_tc::register_tc_scheme!`]:
//!
//! - [`DKG_SCHEME_NAME`] = `"CMP20-ECDSA-P256"` (non-interactive DKG) —
//!   produces per-party [`Cmp20Share`] + shared public key.
//! - [`SIGN_SCHEME_NAME`] = `"CMP20-ECDSA-P256-SIGN"` — produces a
//!   standard 64-byte `(r, s)` ECDSA signature verifiable with the
//!   `p256` crate.
//!
//! See the module-level docs of [`keygen`], [`sign`], [`mta`] for what
//! is implemented and what is omitted. In short: the Feldman VSS,
//! Lagrange interpolation, and threshold-ECDSA combine are all real;
//! the MtA sub-round is a simplified in-process stub (products computed
//! in the clear) rather than a Paillier-based homomorphic MtA, matching
//! the GG18 crate's deferred-Paillier approach.

pub mod error;
pub mod keygen;
pub mod lagrange;
pub mod mta;
pub mod scheme;
pub mod share;
pub mod sign;
pub mod vss;

pub use scheme::{Cmp20EcdsaP256, Cmp20EcdsaP256Sign};
pub use share::Cmp20Share;

/// Canonical scheme name for CMP20 DKG over P-256.
pub const DKG_SCHEME_NAME: &str = "CMP20-ECDSA-P256";

/// Canonical scheme name for CMP20 signing over P-256.
pub const SIGN_SCHEME_NAME: &str = "CMP20-ECDSA-P256-SIGN";
