//! JSON-RPC method handlers.
//!
//! Each submodule covers one interface group (plugin, hash, cipher, …).
//! Handlers are plain async functions that take the daemon-owned
//! [`Confium`] and the parsed params, returning a JSON result value or
//! an [`RpcError`].
//!
//! Methods that mirror C-FFI calls that are not yet wired in
//! `confium-core` use the [`pending_method!`] macro below. As the core
//! lands each interface, the matching handler becomes a thin adapter —
//! no dispatch change is needed.

pub mod aead;
pub mod attributes;
pub mod audit;
pub mod cipher;
pub mod composite;
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

/// Generate an async stub handler that returns an `Engine` error with
/// the given `(method_name, reason)` pair.
///
/// Why a macro: 29 daemon handlers across 7 modules all returned
/// the same boilerplate ("X requires Y (pending)"). The macro keeps
/// the message format consistent and the call site one line. Each
/// pending handler is its own `pub async fn` so the dispatch table
/// (which takes function pointers) sees them as first-class items.
///
/// When a handler moves from pending to real, delete the macro
/// invocation and write the real `pub async fn` in its place.
#[macro_export]
macro_rules! pending_method {
    ($name:ident, $method:literal, $reason:literal) => {
        pub async fn $name(
            _cfm: $crate::server::SharedConfium,
            _params: serde_json::Value,
        ) -> std::result::Result<serde_json::Value, $crate::error::RpcError> {
            Err($crate::error::RpcError::Engine {
                message: format!("{} {}", $method, $reason),
            })
        }
    };
}

