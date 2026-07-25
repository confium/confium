//! AEAD methods: `aead_create`, `aead_encrypt_update`, `aead_decrypt_update`, `aead_finalize`.
//!
//! Skeleton handlers pending per-connection handle management.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn aead_create(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "aead_create requires per-connection handle management (pending)".to_string(),
    })
}

pub async fn aead_encrypt_update(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "aead_encrypt_update requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn aead_decrypt_update(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "aead_decrypt_update requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn aead_finalize(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "aead_finalize requires per-connection handle management (pending)".to_string(),
    })
}
