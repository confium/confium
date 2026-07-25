//! FROST threshold signature scheme over ed25519 (draft-irtf-cfrg-frost).
//!
//! A real cryptographic implementation of FROST, registered with the
//! [`confium_tc`] link-time scheme registry under two names:
//!
//! - [`sign::SCHEME_NAME`] = `"FROST-ed25519"` — threshold signing.
//!   Produces a standard RFC-8032 ed25519 signature `(R, z)` verifiable
//!   by any conformant verifier (e.g. `ed25519-dalek`).
//!
//! - [`dkg::SCHEME_NAME`] = `"FROST-ed25519-dkg"` — distributed key
//!   generation via Pedersen / Feldman VSS. Produces a per-party share
//!   plus the aggregate public key, encoded in the session's
//!   [`confium_tc::Session::result`] as a length-prefixed blob
//!   (`pubkey || share`). Pass that blob directly into a signing
//!   session's [`confium_tc::SessionParams::local_share`].
//!
//! ## Protocol at a glance
//!
//! ### DKG (2 rounds)
//!
//! 1. Each party generates a degree-`T-1` VSS polynomial, broadcasts its
//!    Feldman commitment list, and directs per-peer share fragments.
//! 2. Each party verifies the fragments, aggregates them, and sums the
//!    commitment-list constant terms to get the aggregate public key.
//!
//! ### Signing (3 rounds)
//!
//! 1. Each party broadcasts nonce commitments `(D_i, E_i)`.
//! 2. Each party receives all commitments, derives binding factors, the
//!    group commitment `R`, the challenge `c = SHA-512(R ‖ A ‖ M)`,
//!    computes `z_i = d_i + ρ_i·e_i + λ_i·s_i·c`, and broadcasts it.
//! 3. Each party aggregates `z = Σ z_i`, verifies `z·B == R + c·A`, and
//!    emits `(R, z)`.
//!
//! ## Status / deviations
//!
//! See the module-level notes in [`dkg`] and [`sign`] for the full list
//! of deviations from the textbook FROST protocol. The headline gaps:
//!
//! - **No DKG complaint round.** Byzantine VSS senders are silently
//!   excluded; honest parties still converge on the same key.
//! - **Nonce generation uses `OsRng`**, not the spec's deterministic
//!   H3 derivation.
//! - **Per-party share-response verification is partial.** The aggregate
//!   signature is always verified; identifying which peer was byzantine
//!   requires distributing per-party public shares during DKG, which is
//!   future work.

pub mod dkg;
pub mod error;
pub mod group;
pub mod polynomial;
pub mod sign;
pub mod transcript;

// Re-export the scheme types and the DKG output parser for callers that
// want to drive the scheme directly (the test harness does this).
pub use dkg::FrostEd25519Dkg;
pub use dkg::parse_output as parse_dkg_output;
pub use sign::FrostEd25519;

/// Convenience: the canonical name of the signing scheme, as a `&'static str`.
pub const SIGN_SCHEME: &str = sign::SCHEME_NAME;

/// Convenience: the canonical name of the DKG scheme, as a `&'static str`.
pub const DKG_SCHEME: &str = dkg::SCHEME_NAME;
