//! Signature methods.
//!
//! Skeleton handlers pending per-connection handle management.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::SharedConfium;

pub async fn signature_keypair_generate(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "signature_keypair_generate requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn signature_signer_update(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "signature_signer_update requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn signature_signer_finalize(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "signature_signer_finalize requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn signature_verifier_update(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "signature_verifier_update requires per-connection handle management (pending)"
            .to_string(),
    })
}

pub async fn signature_verifier_finalize(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "signature_verifier_finalize requires per-connection handle management (pending)"
            .to_string(),
    })
}
