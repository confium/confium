//! Keystore methods.
//!
//! Skeleton handlers pending per-connection handle management.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn keystore_create(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "keystore_create requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn keystore_put_secret(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "keystore_put_secret requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn keystore_get_secret(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "keystore_get_secret requires per-connection handle management (pending)"
            .to_string(),
    })
}
