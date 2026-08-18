//! Executable scope conditions (SIGNATIF §11 `scope-conditions`).
//!
//! A scope may carry **scope conditions** — executable predicates
//! evaluated at verification time against the content and context of
//! the artifact. An artifact signed by a key whose scope conditions
//! are not met fails verification, *regardless of cryptographic
//! signature validity* — this is one of the pipeline's hard checks.
//!
//! The expression language is a deterministic subset of JSON Logic
//! (the Annex E reference choice): `var` paths over the evaluation
//! context, numeric/string comparisons, and boolean combinators.
//! Determinism (§11 `condition-determinism`): the evaluation context
//! is fully determined by the artifact and its chain — payload,
//! artifact id, signer reference, dimension, and the signer's
//! attestation timestamp. No wall-clock, no external state.

use serde_json::Value;

use crate::error::{SignatifError, SignatifResult};

/// The evaluation context for scope conditions: everything the
/// artifact and its chain determine, and nothing else.
#[derive(Debug, Clone)]
pub struct ConditionContext {
    /// The JSON evaluation root: `payload`, `artifact_id`,
    /// `signer_cert_ref`, `dimension`, and `attested_at` (RFC 3339).
    pub root: Value,
}

impl ConditionContext {
    /// Build the context from an artifact's facts.
    ///
    /// # Errors
    ///
    /// Never fails; kept symmetrical with the other constructors.
    pub fn new(
        payload: &Value,
        artifact_id: &str,
        signer_cert_ref: &str,
        dimension: &str,
        attested_at: &str,
    ) -> Self {
        Self {
            root: serde_json::json!({
                "payload": payload,
                "artifact_id": artifact_id,
                "signer_cert_ref": signer_cert_ref,
                "dimension": dimension,
                "attested_at": attested_at,
            }),
        }
    }
}

/// Evaluate one condition expression against a context.
///
/// Supported operators (JSON Logic subset):
/// `{">=": [a, b]}`, `>`, `<=`, `<`, `{"==": [a, b]}`, `!=`,
/// `{"and": [...]}`, `{"or": [...]}`, `{"!": expr}`, `{"!!": expr}`,
/// `{"var": "dotted.path"}`. Numbers compare numerically; mixed
/// number/string compares equal only on identical string forms;
/// anything else compares by `Value` equality.
///
/// # Errors
///
/// Encoding errors for malformed expressions (unknown operator, bad
/// arity, non-string `var` path). Malformed expressions are errors,
/// not `false` — a condition that cannot be evaluated fails closed.
pub fn evaluate_condition(expr: &Value, ctx: &ConditionContext) -> SignatifResult<bool> {
    let obj = expr
        .as_object()
        .ok_or_else(|| SignatifError::Encoding("condition must be an object".into()))?;
    let (op, args) = obj
        .iter()
        .next()
        .ok_or_else(|| SignatifError::Encoding("condition object is empty".into()))?;
    match op.as_str() {
        "var" => Err(SignatifError::Encoding(
            "var is only valid as an operand, not a top-level condition".into(),
        )),
        "!" => Ok(!evaluate_condition(args, ctx)?),
        "!!" => evaluate_condition(args, ctx),
        "and" => {
            let list = args
                .as_array()
                .ok_or_else(|| SignatifError::Encoding("and expects an array".into()))?;
            let mut ok = true;
            for sub in list {
                ok = ok && evaluate_condition(sub, ctx)?;
            }
            Ok(ok)
        }
        "or" => {
            let list = args
                .as_array()
                .ok_or_else(|| SignatifError::Encoding("or expects an array".into()))?;
            let mut ok = false;
            for sub in list {
                ok = ok || evaluate_condition(sub, ctx)?;
            }
            Ok(ok)
        }
        ">=" | ">" | "<=" | "<" | "==" | "!=" => {
            let list = args
                .as_array()
                .ok_or_else(|| SignatifError::Encoding(format!("{op} expects an array")))?;
            if list.len() != 2 {
                return Err(SignatifError::Encoding(format!(
                    "{op} expects two operands"
                )));
            }
            let a = resolve_operand(&list[0], ctx)?;
            let b = resolve_operand(&list[1], ctx)?;
            let cmp = compare(&a, &b);
            Ok(match op.as_str() {
                ">=" => cmp != std::cmp::Ordering::Less,
                ">" => cmp == std::cmp::Ordering::Greater,
                "<=" => cmp != std::cmp::Ordering::Greater,
                "<" => cmp == std::cmp::Ordering::Less,
                "==" => cmp == std::cmp::Ordering::Equal,
                _ => cmp != std::cmp::Ordering::Equal,
            })
        }
        other => Err(SignatifError::Encoding(format!(
            "unsupported condition operator {other}"
        ))),
    }
}

/// Evaluate every condition; all must hold.
///
/// # Errors
///
/// Propagates the first malformed or failing condition's error. A
/// failing condition is an [`SignatifError::HardCheck`].
pub fn evaluate_all(conditions: &[Value], ctx: &ConditionContext) -> SignatifResult<()> {
    for (i, expr) in conditions.iter().enumerate() {
        let ok = evaluate_condition(expr, ctx)?;
        if !ok {
            return Err(SignatifError::HardCheck(format!(
                "scope_condition[{i}] not satisfied"
            )));
        }
    }
    Ok(())
}

fn resolve_operand(v: &Value, ctx: &ConditionContext) -> SignatifResult<Value> {
    match v {
        Value::Object(obj) => {
            if let Some(Value::String(path)) = obj.get("var") {
                let mut current = &ctx.root;
                for segment in path.split('.') {
                    current = current.get(segment).ok_or_else(|| {
                        SignatifError::Encoding(format!("var path `{path}` not found"))
                    })?;
                }
                Ok(current.clone())
            } else {
                // Nested expression.
                Ok(Value::Bool(evaluate_condition(v, ctx)?))
            }
        }
        other => Ok(other.clone()),
    }
}

fn compare(a: &Value, b: &Value) -> std::cmp::Ordering {
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        return x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal);
    }
    if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
        return x.cmp(y);
    }
    if a == b {
        std::cmp::Ordering::Equal
    } else {
        // Incomparable, unequal values sort greater to make == false
        // and != true deterministically.
        std::cmp::Ordering::Greater
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> ConditionContext {
        ConditionContext::new(
            &json!({"quantity": 50000, "product": "vaccine-batch-A", "batch": {"id": "LOT-1"}}),
            "art-1",
            "end-1",
            "data",
            "2026-08-18T00:00:00Z",
        )
    }

    #[test]
    fn value_within_range() {
        let c = evaluate_condition(&json!({">=": [{"var": "payload.quantity"}, 10000]}), &ctx())
            .unwrap();
        assert!(c);
        let c = evaluate_condition(&json!({"<": [{"var": "payload.quantity"}, 10000]}), &ctx())
            .unwrap();
        assert!(!c);
    }

    #[test]
    fn nested_paths_and_boolean_combinators() {
        let c = evaluate_condition(
            &json!({"and": [
                {"==": [{"var": "payload.product"}, "vaccine-batch-A"]},
                {"or": [
                    {">=": [{"var": "payload.quantity"}, 10000]},
                    {"==": [{"var": "payload.batch.id"}, "LOT-9"]}
                ]},
            ]}),
            &ctx(),
        )
        .unwrap();
        assert!(c);
    }

    #[test]
    fn signer_and_dimension_visible() {
        let c = evaluate_condition(
            &json!({"==": [{"var": "signer_cert_ref"}, "end-1"]}),
            &ctx(),
        )
        .unwrap();
        assert!(c);
        let c = evaluate_condition(&json!({"==": [{"var": "dimension"}, "data"]}), &ctx()).unwrap();
        assert!(c);
    }

    #[test]
    fn failing_condition_hard_fails() {
        let expr = serde_json::json!({ ">=": [ {"var": "payload.quantity"}, 999999 ] });
        let err = evaluate_all(&[expr], &ctx()).unwrap_err();
        assert!(err.to_string().contains("scope_condition[0]"));
    }

    #[test]
    fn malformed_expressions_fail_closed() {
        assert!(evaluate_condition(&json!("nope"), &ctx()).is_err());
        assert!(evaluate_condition(&json!({"+": [1, 1]}), &ctx()).is_err());
        assert!(
            evaluate_condition(&json!({">=": [{"var": "payload.missing"}, 1]}), &ctx()).is_err()
        );
    }

    #[test]
    fn deterministic_same_context_same_result() {
        let expr = json!({">=": [{"var": "payload.quantity"}, 1]});
        assert_eq!(
            evaluate_condition(&expr, &ctx()).unwrap(),
            evaluate_condition(&expr, &ctx()).unwrap()
        );
    }
}
