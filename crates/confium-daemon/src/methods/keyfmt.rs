//! Key format methods.
//!
//! Skeleton handlers pending per-connection handle management.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn keyfmt_parse(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "keyfmt_parse requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn keyfmt_serialize(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "keyfmt_serialize requires per-connection handle management (pending)".to_string(),
    })
}
