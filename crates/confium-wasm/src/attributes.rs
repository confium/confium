//! `Predicate` — attribute-based threshold policy DSL, browser-side evaluate-only.

use confium_attributes::{evaluate, parse as dsl_parse, Predicate as RustPredicate,
    SignerAttributes};
use wasm_bindgen::prelude::*;

/// Parsed DSL predicate. Construct via [`Predicate::parse`] and evaluate
/// via [`Predicate::satisfied_by`].
#[wasm_bindgen]
pub struct Predicate {
    inner: RustPredicate,
}

#[wasm_bindgen]
impl Predicate {
    /// Parse a DSL expression into a Predicate.
    ///
    /// Examples:
    ///   - `min_count("role:director", 3)`
    ///   - `and(min_count("role:director", 3), min_distinct("region", 3))`
    ///   - `or(any("expertise"), all("emergency"))`
    ///   - `not(none("nationality:cn"))`
    #[wasm_bindgen(constructor)]
    pub fn parse(expr: &str) -> Result<Predicate, JsValue> {
        let inner = dsl_parse(expr).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Self { inner })
    }

    /// Evaluate the predicate against a list of signers. Each signer is a
    /// plain JS object mapping attribute name -> array of values:
    ///
    /// ```js
    /// predicate.satisfiedBy([
    ///   { "role:director": ["yes"], "region": ["europe"] },
    ///   { "role:director": ["yes"], "region": ["americas"] },
    /// ]);
    /// ```
    pub fn satisfied_by(&self, signers_json: &str) -> Result<bool, JsValue> {
        let parsed: Vec<SignerEntry> = serde_json::from_str(signers_json)
            .map_err(|e| JsValue::from_str(&format!("invalid signers JSON: {e}")))?;
        let owned: Vec<SignerAttributes> = parsed
            .into_iter()
            .map(|entry| {
                let mut s = SignerAttributes::new();
                for (k, values) in entry.0 {
                    for v in values {
                        s.add(k.clone(), v);
                    }
                }
                s
            })
            .collect();
        let refs: Vec<&SignerAttributes> = owned.iter().collect();
        Ok(evaluate(&self.inner, &refs))
    }
}

#[derive(serde::Deserialize)]
struct SignerEntry(std::collections::HashMap<String, Vec<String>>);
