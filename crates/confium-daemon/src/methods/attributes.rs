//! Attribute-based threshold predicate methods.
//!
//! `attributes_evaluate` is the second stateless daemon handler
//! (alongside `composite_verify`). It accepts a DSL expression +
//! JSON list of signers, returns whether the predicate is satisfied.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use confium_attributes::{evaluate, parse as dsl_parse, SignerAttributes};
use crate::error::RpcError;
use crate::server::SharedConfium;

/// Request body for `attributes_evaluate`.
#[derive(Debug, Deserialize)]
struct AttributesEvaluateRequest {
    /// DSL expression, e.g. `min_count("role:director", 3)`.
    predicate: String,
    /// JSON array of signer attribute maps. Each signer is an object
    /// mapping attribute name → array of string values, e.g.
    /// `[{"role:director": ["yes"], "region": ["europe"]}, ...]`.
    signers: Vec<Map<String, Value>>,
}

/// Convert a JSON object (`{attr: [vals]}`) into a `SignerAttributes`.
fn signer_from_json(obj: &Map<String, Value>) -> Result<SignerAttributes, RpcError> {
    let mut attrs = SignerAttributes::new();
    for (key, value) in obj {
        let arr = value.as_array().ok_or_else(|| RpcError::InvalidParams {
            detail: format!("attribute '{key}' value must be a JSON array of strings"),
        })?;
        let mut set = HashSet::new();
        for v in arr {
            let s = v.as_str().ok_or_else(|| RpcError::InvalidParams {
                detail: format!("attribute '{key}' has a non-string value"),
            })?;
            set.insert(s.to_string());
        }
        attrs.attrs.insert(key.clone(), set);
    }
    Ok(attrs)
}

/// `attributes_evaluate({ "predicate": "...", "signers": [...] })`
///
/// Returns:
/// ```json
/// { "satisfied": true }
/// ```
pub async fn attributes_evaluate(
    _cfm: SharedConfium,
    params: Value,
) -> std::result::Result<Value, RpcError> {
    let req: AttributesEvaluateRequest = serde_json::from_value(params).map_err(|e| {
        RpcError::InvalidParams {
            detail: format!("attributes_evaluate params: {e}"),
        }
    })?;

    let predicate = dsl_parse(&req.predicate).map_err(|e| RpcError::InvalidParams {
        detail: format!("predicate parse error: {e}"),
    })?;

    let mut signers = Vec::with_capacity(req.signers.len());
    for obj in &req.signers {
        signers.push(signer_from_json(obj)?);
    }
    let refs: Vec<&SignerAttributes> = signers.iter().collect();

    let satisfied = evaluate(&predicate, &refs);
    Ok(json!({ "satisfied": satisfied }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_confium;

    #[tokio::test]
    async fn attributes_evaluate_satisfied() {
        let params = json!({
            "predicate": "min_count(\"role:director\", 3)",
            "signers": [
                {"role:director": ["yes"]},
                {"role:director": ["yes"]},
                {"role:director": ["yes"]},
            ]
        });
        let result = attributes_evaluate(test_confium(), params).await.unwrap();
        assert_eq!(result["satisfied"], json!(true));
    }

    #[tokio::test]
    async fn attributes_evaluate_not_satisfied() {
        let params = json!({
            "predicate": "min_count(\"role:director\", 5)",
            "signers": [
                {"role:director": ["yes"]},
                {"role:director": ["yes"]},
            ]
        });
        let result = attributes_evaluate(test_confium(), params).await.unwrap();
        assert_eq!(result["satisfied"], json!(false));
    }

    #[tokio::test]
    async fn attributes_evaluate_distinct_values() {
        let params = json!({
            "predicate": "min_distinct(\"region\", 3)",
            "signers": [
                {"region": ["europe"]},
                {"region": ["americas"]},
                {"region": ["asia-pacific"]},
            ]
        });
        let result = attributes_evaluate(test_confium(), params).await.unwrap();
        assert_eq!(result["satisfied"], json!(true));
    }

    #[tokio::test]
    async fn attributes_evaluate_rejects_bad_predicate() {
        let params = json!({
            "predicate": "bogus_function(\"arg\")",
            "signers": [],
        });
        let result = attributes_evaluate(test_confium(), params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn attributes_evaluate_rejects_missing_fields() {
        let result = attributes_evaluate(test_confium(), json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn attributes_evaluate_rejects_non_array_signer_value() {
        let params = json!({
            "predicate": "any(\"x\")",
            "signers": [{"x": "scalar"}],
        });
        let result = attributes_evaluate(test_confium(), params).await;
        assert!(result.is_err());
    }
}

