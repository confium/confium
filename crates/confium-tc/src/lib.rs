//! Confium threshold-cryptography primitives — the headline deliverable.
//!
//! This crate supplies:
//! - the `tc-session`, `tc-round`, `tc-share` FFI surface
//! - session state machine helpers (round orchestration, message routing)
//! - reference implementations of common TC schemes (FROST, GG18) — eventually
//!
//! Built on top of: `confium-net` (transport), `confium-store` (share
//! persistence), `confium-api` (shared types). Plugin authors implement
//! the per-scheme logic; Confium supplies everything else.
//!
//! See `TODO.roadmap/04-threshold-cryptography.md` — this is the entire
//! reason Confium exists.
//!
//! Today this is a placeholder skeleton.
