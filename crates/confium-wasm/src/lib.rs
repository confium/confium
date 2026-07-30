//! Browser/Node.js **verifier** package for Confium.
//!
//! wasm-bindgen surface, `wasm32-unknown-unknown` target, verifier-only by
//! design. Browsers verify; servers sign.
//!
//! Each subsystem is gated by a `verify-*` Cargo feature so consumers can
//! tree-shake aggressively. All features are on by default for out-of-the-box
//! ergonomics.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use wasm_bindgen::prelude::*;

#[cfg(feature = "verify-composite")]
mod composite;

#[cfg(feature = "verify-composite")]
pub use composite::{CompositeSignature, CompositeVerificationResult};

#[cfg(feature = "verify-transparency")]
mod transparency;

#[cfg(feature = "verify-transparency")]
pub use transparency::{
    InclusionProof, MerkleTree, compute_artifact_hash, compute_leaf_hash, tree_head_from_json,
    verify_inclusion_with_head,
};

#[cfg(feature = "verify-attributes")]
mod attributes;

#[cfg(feature = "verify-attributes")]
pub use attributes::Predicate;

#[cfg(feature = "verify-pki")]
mod pki;

#[cfg(feature = "verify-pki")]
pub use pki::{Certificate, SignedData};

/// Package version (mirrors the Cargo version).
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Confium-core crate version this WASM blob was built against.
#[wasm_bindgen]
pub fn core_version() -> String {
    "0.2.0".to_string()
}

/// Canonicalize XML per RFC 3076 (Canonical XML 1.0).
#[wasm_bindgen]
pub fn canonicalize_xml(xml: &str) -> Result<String, JsValue> {
    confium_pki::xmldsig::canonicalize(xml)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Canonicalize XML per Exclusive C14N (RFC 3741).
#[wasm_bindgen]
pub fn canonicalize_exclusive_xml(xml: &str) -> Result<String, JsValue> {
    confium_pki::xmldsig::canonicalize_exclusive(xml)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
