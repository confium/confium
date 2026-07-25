//! RNG methods: `rng_create`, `rng_generate`.
//!
//! Skeleton handlers pending per-connection handle management.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn rng_create(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "rng_create requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn rng_generate(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "rng_generate requires per-connection handle management (pending)".to_string(),
    })
}
