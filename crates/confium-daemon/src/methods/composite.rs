//! Composite signature verification methods.
//!
//! `composite_verify` is the first end-to-end crypto method in the
//! daemon: it accepts a JSON envelope + base64 message, runs the
//! built-in Ed25519 + ECDSA-P256 verifiers, and returns a structured
//! per-component result.
//!
//! Stateless and self-contained — no handle store, no plugin loading.
//! This is the shape we want for every "verifier" JSON-RPC method.

use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::RpcError;
use crate::server::SharedConfium;

/// Request body for `composite_verify`.
#[derive(Debug, Deserialize)]
struct CompositeVerifyRequest {
    /// Base64-encoded signed message.
    message: String,
    /// JSON-serialized [`confium_composite::CompositeSignature`].
    composite: Value,
}

/// `composite_verify({ "message": "<base64>", "composite": {...} })`
///
/// Returns:
/// ```json
/// {
///   "all_verified": true,
///   "per_component": [
///     { "index": 0, "algorithm": "Ed25519", "verified": true, "error": null }
///   ]
/// }
/// ```
pub async fn composite_verify(
    _cfm: SharedConfium,
    params: Value,
) -> std::result::Result<Value, RpcError> {
    let req: CompositeVerifyRequest =
        serde_json::from_value(params).map_err(|e| RpcError::InvalidParams {
            detail: format!("composite_verify params: {e}"),
        })?;

    let message = general_purpose::STANDARD
        .decode(req.message.as_bytes())
        .map_err(|e| RpcError::InvalidParams {
            detail: format!("message: not valid base64: {e}"),
        })?;

    let composite_json = serde_json::to_string(&req.composite).unwrap_or_else(|_| "{}".into());
    let composite: confium_composite::CompositeSignature = serde_json::from_str(&composite_json)
        .map_err(|e| RpcError::InvalidParams {
            detail: format!("composite: invalid envelope: {e}"),
        })?;

    let result = composite
        .verify(&message, |alg, pk, msg, sig| match alg {
            confium_composite::ED25519 => confium_composite::ed25519_verifier(alg, pk, msg, sig),
            confium_composite::ECDSA_P256 => confium_composite::p256_verifier(alg, pk, msg, sig),
            other => Err(format!(
                "no builtin verifier for algorithm '{other}' \
                 (composite_verify supports Ed25519 and ECDSA-P256)"
            )),
        })
        .map_err(|e| RpcError::Engine {
            message: format!("composite verify: {e}"),
        })?;

    let per_component: Vec<Value> = result
        .per_component
        .iter()
        .map(|c| {
            json!({
                "index": c.index,
                "algorithm": c.algorithm,
                "verified": c.verified,
                "error": c.error,
            })
        })
        .collect();

    Ok(json!({
        "all_verified": result.all_verified,
        "per_component": per_component,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_confium;
    use base64::{Engine as _, engine::general_purpose};
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use rand_core::OsRng;

    fn make_ed25519_component(message: &[u8]) -> (Value, Vec<u8>) {
        let signing = SigningKey::generate(&mut OsRng);
        let sig: Signature = signing.sign(message);
        let vk: VerifyingKey = signing.verifying_key();
        let pk_bytes = vk.to_bytes().to_vec();
        let sig_bytes = sig.to_bytes().to_vec();
        let composite = json!({
            "components": [{
                "algorithm": "Ed25519",
                "public_key": pk_bytes,
                "signature": sig_bytes,
            }]
        });
        (composite, message.to_vec())
    }

    #[tokio::test]
    async fn composite_verify_accepts_valid_signature() {
        let message = b"daemon composite_verify integration";
        let (composite, _) = make_ed25519_component(message);
        let msg_b64 = general_purpose::STANDARD.encode(message);

        let result = composite_verify(
            test_confium(),
            json!({ "message": msg_b64, "composite": composite }),
        )
        .await
        .unwrap();

        assert_eq!(result["all_verified"], json!(true));
        assert_eq!(result["per_component"][0]["verified"], json!(true));
        assert_eq!(result["per_component"][0]["algorithm"], "Ed25519");
    }

    #[tokio::test]
    async fn composite_verify_rejects_tampered_message() {
        let message = b"original message";
        let (composite, _) = make_ed25519_component(message);
        let tampered_b64 = general_purpose::STANDARD.encode(b"different message");

        let result = composite_verify(
            test_confium(),
            json!({ "message": tampered_b64, "composite": composite }),
        )
        .await
        .unwrap();

        assert_eq!(result["all_verified"], json!(false));
        assert_eq!(result["per_component"][0]["verified"], json!(false));
        assert!(result["per_component"][0]["error"].is_string());
    }

    #[tokio::test]
    async fn composite_verify_rejects_invalid_base64() {
        let result = composite_verify(
            test_confium(),
            json!({ "message": "not base64 !!!", "composite": {} }),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn composite_verify_rejects_missing_fields() {
        let result = composite_verify(test_confium(), json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn composite_verify_reports_unsupported_algorithm() {
        let composite = json!({
            "components": [{
                "algorithm": "ML-DSA-65",
                "public_key": vec![0u8; 32],
                "signature": vec![0u8; 64],
            }]
        });
        let msg_b64 = general_purpose::STANDARD.encode(b"msg");
        let result = composite_verify(
            test_confium(),
            json!({ "message": msg_b64, "composite": composite }),
        )
        .await
        .unwrap();
        assert_eq!(result["all_verified"], json!(false));
        let err = result["per_component"][0]["error"].as_str().unwrap();
        assert!(err.contains("no builtin verifier"));
    }
}
