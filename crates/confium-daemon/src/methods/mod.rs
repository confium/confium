//! JSON-RPC method handlers.
//!
//! Each submodule covers one interface group (plugin, hash, cipher, …).
//! Handlers are plain async functions that take the daemon-owned
//! [`Confium`] and the parsed params, returning a JSON result value or
//! an [`RpcError`].
//!
//! Methods that mirror C-FFI calls that are not yet wired in
//! `confium-core` return an `Engine` error with a "not yet implemented"
//! message. As the core lands each interface, the matching handler
//! becomes a thin adapter — no dispatch change is needed.

pub mod aead;
pub mod audit;
pub mod cipher;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod keyfmt;
pub mod keystore;
pub mod meta;
pub mod plugin;
pub mod registry;
pub mod rng;
pub mod signature;
pub mod tc;
