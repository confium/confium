//! Confium Network: transport abstraction for multi-party protocols.
//!
//! Threshold-cryptography sessions need reliable, authenticated byte
//! streams between parties. Confium supplies the transport so plugin
//! authors don't roll their own socket code.
//!
//! Transports planned: `inproc`, `tcp`, `tcp+tls`, `quic`, `ws`, `wss`,
//! `mock`. Each registers itself at link time via the same pattern used
//! for crypto interfaces (see `confium-core::ffi::registry`).
//!
//! See `TODO.roadmap/05-networking-primitives.md` for the design.
//!
//! Today this is a placeholder skeleton.
