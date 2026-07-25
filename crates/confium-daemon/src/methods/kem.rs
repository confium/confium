//! KEM (Key Encapsulation Mechanism) methods.
//!
//! Skeleton handlers pending per-connection handle management.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn kem_keypair_generate(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "kem_keypair_generate requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn kem_encapsulate(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "kem_encapsulate requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn kem_decapsulate(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "kem_decapsulate requires per-connection handle management (pending)".to_string(),
    })
}
