//! `CompositeSignature` — PQ-migration composite signature verifier for
//! browser/Node.js consumers.

use confium_composite::{CompositeSignature as RustComposite, VerificationResult};
use wasm_bindgen::prelude::*;

/// A composite signature — multiple algorithm components over the same
/// message. Construct via [`CompositeSignature::from_json`] (the canonical
/// wire format) and verify with [`CompositeSignature::verify`].
#[wasm_bindgen]
pub struct CompositeSignature {
    inner: RustComposite,
}

#[wasm_bindgen]
impl CompositeSignature {
    /// Parse a composite signature from its canonical JSON wire format.
    ///
    /// ```json
    /// { "components": [
    ///   { "algorithm": "Ed25519",
    ///     "public_key": "<base64>",
    ///     "signature": "<base64>" },
    ///   ...
    /// ] }
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn from_json(json: &str) -> Result<CompositeSignature, JsValue> {
        let inner: RustComposite = serde_json::from_str(json)
            .map_err(|e| js_err(&format!("invalid composite signature JSON: {e}")))?;
        Ok(Self { inner })
    }

    /// Number of components.
    #[wasm_bindgen(getter)]
    pub fn component_count(&self) -> usize {
        self.inner.component_count()
    }

    /// Algorithm identifiers in component order.
    #[wasm_bindgen(getter)]
    pub fn algorithms(&self) -> Vec<String> {
        self.inner
            .algorithms()
            .into_iter()
            .map(String::from)
            .collect()
    }

    /// Verify all components against `message`. Returns a
    /// [`CompositeVerificationResult`] describing per-component outcomes.
    ///
    /// Built-in verifiers: Ed25519 + ECDSA-P256. Unknown algorithms are
    /// reported as failed components. JS callers needing ML-DSA-65 or
    /// SLH-DSA verification must preprocess the composite and supply
    /// their own verifier callback (Phase 2D).
    #[wasm_bindgen]
    pub fn verify(&self, message: &[u8]) -> Result<CompositeVerificationResult, JsValue> {
        let result = self
            .inner
            .verify(message, |algorithm, public_key, m, signature| {
                if algorithm == confium_composite::ED25519 {
                    confium_composite::ed25519_verifier(algorithm, public_key, m, signature)
                } else if algorithm == "ECDSA-P256" || algorithm == "ECDSA" {
                    p256_verifier(public_key, m, signature)
                } else {
                    Err(format!("unsupported algorithm: {algorithm}"))
                }
            })
            .map_err(|e| js_err(&e.to_string()))?;
        Ok(CompositeVerificationResult { inner: result })
    }
}

/// Verify an ECDSA-P256 signature. `public_key` is SEC1-encoded verifying
/// key (compressed 33 bytes or uncompressed 65 bytes). `signature` is
/// DER-encoded. SHA-256 is used as the digest.
fn p256_verifier(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;
    let sig = Signature::from_der(signature).map_err(|e| format!("invalid DER signature: {e}"))?;
    vk.verify(message, &sig).map_err(|e| format!("verify: {e}"))
}

/// Per-component + aggregate verification outcome.
#[wasm_bindgen]
pub struct CompositeVerificationResult {
    inner: VerificationResult,
}

#[wasm_bindgen]
impl CompositeVerificationResult {
    /// True iff every component verified.
    #[wasm_bindgen(getter)]
    pub fn all_verified(&self) -> bool {
        self.inner.all_verified
    }

    /// JSON array of `{ index, algorithm, verified, error? }` entries —
    /// one per component. Returned as a JSON string because wasm-bindgen
    /// doesn't natively marshal Vec<struct-with-Option> across the boundary.
    #[wasm_bindgen(getter)]
    pub fn per_component_json(&self) -> String {
        // Build manually — the upstream `ComponentResult` doesn't derive
        // Serialize, and we don't want a breaking change to a published crate.
        let entries: Vec<String> = self
            .inner
            .per_component
            .iter()
            .map(|c| {
                let alg = serde_json::to_string(&c.algorithm).unwrap_or_else(|_| "\"\"".into());
                let err = match &c.error {
                    Some(e) => format!(
                        ",\"error\":{}",
                        serde_json::to_string(e).unwrap_or_else(|_| "null".into())
                    ),
                    None => String::new(),
                };
                format!(
                    "{{\"index\":{},\"algorithm\":{},\"verified\":{}{}}}",
                    c.index, alg, c.verified, err
                )
            })
            .collect();
        format!("[{}]", entries.join(","))
    }
}

fn js_err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}
