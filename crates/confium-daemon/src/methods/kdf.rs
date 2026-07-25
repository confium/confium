//! KDF methods: `kdf_create`, `kdf_derive`.
//!
//! Skeleton handlers pending per-connection handle management.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn kdf_create(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "kdf_create requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn kdf_derive(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "kdf_derive requires per-connection handle management (pending)".to_string(),
    })
}
