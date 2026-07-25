//! Cipher methods: `cipher_create`, `cipher_update`, `cipher_finalize`.
//!
//! Skeleton handlers. The core `Cipher` API requires a loaded provider
//! and per-connection handle management; these handlers return an
//! `Engine` error until the handle store is wired.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn cipher_create(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "cipher_create requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn cipher_update(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "cipher_update requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn cipher_finalize(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "cipher_finalize requires per-connection handle management (pending)".to_string(),
    })
}
