//! Registry methods.
//!
//! Skeleton handlers pending integration with the `confium-registry`
//! crate.

use serde_json::{Value, json};

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn registry_install(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "registry_install is not yet wired (pending registry integration)".to_string(),
    })
}

pub async fn registry_search(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Ok(json!({ "results": [] }))
}
