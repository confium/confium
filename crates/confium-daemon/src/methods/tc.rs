//! Threshold computing (TC) methods.
//!
//! Skeleton handlers pending per-connection handle management and the
//! TC session store.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn tc_session_create(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "tc_session_create requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn tc_session_round(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "tc_session_round requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn tc_session_result(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "tc_session_result requires per-connection handle management (pending)"
            .to_string(),
    })
}
