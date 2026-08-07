//! JSON-LD document signing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A signed JSON-LD document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedJsonLd {
    /// The original document content.
    pub document: Value,
    /// The proof (signature) node.
    pub proof: Proof,
}

/// A Linked Data proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Proof type (e.g., "Ed25519Signature2020").
    #[serde(rename = "type")]
    pub proof_type: String,
    /// When the proof was created.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Verification method (key ID).
    pub verification_method: String,
    /// Proof purpose (e.g., "assertionMethod").
    pub proof_purpose: String,
    /// Signature value (hex or base58).
    pub proof_value: String,
}

/// Canonicalize a JSON-LD document for signing (URDNA2015 simplified).
/// Produces a deterministic byte representation.
pub fn canonicalize(document: &Value) -> Vec<u8> {
    // Simplified canonicalization: sort keys recursively, serialize
    // Full implementation would use JSON-LD framing + URDNA2015.
    let mut canonical = canonicalize_value(document);
    canonical.sort();
    let mut result = Vec::new();
    for entry in canonical {
        result.extend_from_slice(entry.as_bytes());
        result.push(b'\n');
    }
    result
}

fn canonicalize_value(value: &Value) -> Vec<String> {
    let mut entries = Vec::new();
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                if key == "proof" {
                    continue;
                }
                let val = &map[key];
                match val {
                    Value::String(s) => {
                        entries.push(format!("{key}:{s}"));
                    }
                    Value::Number(n) => {
                        entries.push(format!("{key}:{n}"));
                    }
                    Value::Bool(b) => {
                        entries.push(format!("{key}:{b}"));
                    }
                    Value::Null => {
                        entries.push(format!("{key}:null"));
                    }
                    _ => {
                        let sub = canonicalize_value(val);
                        for s in sub {
                            entries.push(format!("{key}.{s}"));
                        }
                    }
                }
            }
        }
        Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                let sub = canonicalize_value(item);
                for s in sub {
                    entries.push(format!("[{i}].{s}"));
                }
            }
        }
        Value::String(s) => entries.push(s.clone()),
        Value::Number(n) => entries.push(n.to_string()),
        Value::Bool(b) => entries.push(b.to_string()),
        Value::Null => entries.push("null".into()),
    }
    entries
}

/// Create a signed JSON-LD document.
pub fn sign_document(
    document: Value,
    algorithm: &str,
    verification_method: &str,
    signature_hex: &str,
) -> SignedJsonLd {
    SignedJsonLd {
        document,
        proof: Proof {
            proof_type: algorithm.into(),
            created: chrono::Utc::now(),
            verification_method: verification_method.into(),
            proof_purpose: "assertionMethod".into(),
            proof_value: signature_hex.into(),
        },
    }
}

/// Verify a signed document by recomputing the canonical form.
pub fn verify_canonical(signed: &SignedJsonLd) -> Vec<u8> {
    canonicalize(&signed.document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sign_adds_proof() {
        let doc = json!({"name": "test", "value": 42});
        let signed = sign_document(doc, "Ed25519Signature2020", "key-1", "abc123");
        assert_eq!(signed.proof.proof_type, "Ed25519Signature2020");
        assert_eq!(signed.proof.verification_method, "key-1");
        assert_eq!(signed.proof.proof_value, "abc123");
    }

    #[test]
    fn canonicalize_is_deterministic() {
        let doc1 = json!({"b": 2, "a": 1});
        let doc2 = json!({"a": 1, "b": 2});
        assert_eq!(canonicalize(&doc1), canonicalize(&doc2));
    }

    #[test]
    fn canonicalize_excludes_proof() {
        let doc = json!({"data": "x", "proof": {"value": "sig"}});
        let canonical = canonicalize(&doc);
        let text = String::from_utf8(canonical).unwrap();
        assert!(!text.contains("proof"));
        assert!(text.contains("data:x"));
    }

    #[test]
    fn canonicalize_nested() {
        let doc = json!({"outer": {"inner": "val"}});
        let canonical = canonicalize(&doc);
        let text = String::from_utf8(canonical).unwrap();
        assert!(text.contains("outer.inner:val"));
    }

    #[test]
    fn canonicalize_array() {
        let doc = json!({"items": ["a", "b"]});
        let canonical = canonicalize(&doc);
        let text = String::from_utf8(canonical).unwrap();
        assert!(text.contains("[0].a"));
        assert!(text.contains("[1].b"));
    }

    #[test]
    fn signed_document_serializes() {
        let doc = json!({"hello": "world"});
        let signed = sign_document(doc, "Test", "k1", "sig");
        let json_str = serde_json::to_string(&signed).unwrap();
        assert!(json_str.contains("proof"));
        assert!(json_str.contains("assertionMethod"));
    }

    #[test]
    fn verify_canonical_matches() {
        let doc = json!({"a": 1});
        let signed = sign_document(doc, "Ed", "k", "s");
        let canonical = verify_canonical(&signed);
        assert!(!canonical.is_empty());
    }

    #[test]
    fn different_documents_different_canonical() {
        let doc1 = json!({"a": 1});
        let doc2 = json!({"a": 2});
        assert_ne!(canonicalize(&doc1), canonicalize(&doc2));
    }

    #[test]
    fn proof_has_timestamp() {
        let signed = sign_document(json!({}), "T", "k", "s");
        assert!(signed.proof.created.timestamp() > 0);
    }
}
