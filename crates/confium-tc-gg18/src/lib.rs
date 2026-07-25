//! GG18 threshold ECDSA over P-256 (Gennaro & Goldfeder 2018, eprint 2019/114).
//!
//! Wired as a [`confium_tc::registry::TcScheme`] plugin with two scheme
//! names registered through [`confium_tc::register_tc_scheme!`]:
//!
//! - `GG18-ECDSA-P256` (DKG via Feldman VSS) — produces per-party
//!   [`Gg18Share`] + shared public key.
//! - `GG18-ECDSA-P256-SIGN` — produces a standard 64-byte `(r, s)`
//!   ECDSA signature verifiable with the `p256` crate.
//!
//! See the module-level docs of [`keygen`], [`sign`], [`vss`], [`mta`]
//! for what is implemented and what is omitted. In short: the Feldman
//! VSS, Lagrange interpolation, and threshold-ECDSA combine are all
//! real; the MtA sub-round is a simplified in-process stub (nonce
//! reveal in the clear) rather than a Paillier-based homomorphic MtA.

pub mod error;
pub mod keygen;
pub mod lagrange;
pub mod mta;
pub mod scheme;
pub mod share;
pub mod sign;
pub mod vss;

pub use scheme::{Gg18EcdsaP256, Gg18EcdsaP256Sign};
pub use share::Gg18Share;

/// Canonical scheme name for GG18 DKG over P-256.
pub const DKG_SCHEME_NAME: &str = "GG18-ECDSA-P256";

/// Canonical scheme name for GG18 signing over P-256.
pub const SIGN_SCHEME_NAME: &str = "GG18-ECDSA-P256-SIGN";
