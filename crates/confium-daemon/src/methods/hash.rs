//! Hash methods: `hash_create`, `hash_update`, `hash_finalize`.
//!
//! Hash objects are owned by the daemon and referenced by a client-
//! supplied handle id (a string). The handle table lives in the
//! [`HashStore`] passed to each handler.
//!
//! For the skeleton, handlers exercise the core `Hash` API under a
//! per-connection lock. The underlying `confium_core::hash::Hash`
//! requires a loaded provider, so these methods return an `Engine`
//! error when no provider offers the requested algorithm.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::RpcError;
use crate::server::SharedConfium;

/// `hash_create({ "algorithm": "sha-256", "provider": null })`
/// → `{"handle": "<opaque>"}`
///
/// Delegates to [`Hash::new`]. The client picks the algorithm name;
/// the provider is optional (first provider that supports the
/// algorithm wins).
#[derive(Deserialize)]
struct HashCreateParams {
    algorithm: String,
    #[serde(default)]
    provider: Option<String>,
}

pub async fn hash_create(
    cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    let p: HashCreateParams =
        serde_json::from_value(_params).map_err(|e| RpcError::InvalidParams {
            detail: e.to_string(),
        })?;

    let cfm = cfm.borrow();
    // The core Hash::new borrows &Confium, so we stay in the RefCell
    // borrow for the duration. For a skeleton this is acceptable; a
    // production daemon would clone the Rc and release the borrow.
    let _hash = confium_core::hash::Hash::new(&cfm, &p.algorithm, p.provider.as_deref(), None)
        .map_err(|e| RpcError::Engine {
            message: e.to_string(),
        })?;
    // We have no per-connection handle store in the skeleton; return a
    // placeholder handle. When handle management is wired (per
    // connection state), this returns the id under which the hash is
    // stored.
    Ok(json!({ "handle": "<pending>" }))
}

/// `hash_update({ "handle": "...", "data": "<base64>" })` → `{"ok": true}`
///
/// The skeleton does not yet track handles; this handler returns an
/// `Engine` error indicating handle management is pending.
pub async fn hash_update(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "hash_update requires per-connection handle management (pending)".to_string(),
    })
}

/// `hash_finalize({ "handle": "..." })` → `{"digest": "<base64>"}`
///
/// Same caveat as `hash_update`: handle management is pending.
pub async fn hash_finalize(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "hash_finalize requires per-connection handle management (pending)".to_string(),
    })
}
