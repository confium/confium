//! Method dispatch table.
//!
//! Each JSON-RPC method name is mapped to a handler function. The
//! handler receives the parsed [`RpcRequest`] and a reference to the
//! daemon-owned [`Confium`] instance. Handlers return a
//! JSON-serializable result value or a [`RpcError`].
//!
//! Adding a new method is a single entry in [`Dispatch::new`]:
//! register the name and the handler. No match arm, no central switch.
//! This is the open/closed shape the daemon aims for — extension is
//! registration, not modification.

use std::collections::HashMap;
use std::rc::Rc;

use serde_json::Value;

use crate::error::RpcError;
use crate::methods;
use crate::server::SharedConfium;

/// Type alias for a handler. Handlers are async so they can await
/// slow operations (audit subscription setup, keystore I/O, etc.)
/// without blocking other connections.
///
/// The handler is `!Send` because `Confium` is `!Send` (plugin
/// interfaces hold `Rc<dyn Any>`). The entire dispatch + connection
/// loop runs on a single [`tokio::task::LocalSet`].
pub type Handler = Rc<
    dyn Fn(
        SharedConfium,
        Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<Value, RpcError>>>,
    >,
>;

/// The dispatch table. Maps method name → handler.
pub struct Dispatch {
    table: HashMap<String, Handler>,
}

impl Dispatch {
    /// Build the full dispatch table. New methods are added here.
    pub fn new() -> Self {
        let mut table = HashMap::new();

        // -- meta --
        table.insert("version".to_string(), rc(methods::meta::version));
        table.insert("shutdown".to_string(), rc(methods::meta::shutdown));

        // -- plugin --
        table.insert("plugin_load".to_string(), rc(methods::plugin::plugin_load));
        table.insert(
            "plugin_unload".to_string(),
            rc(methods::plugin::plugin_unload),
        );
        table.insert("plugin_list".to_string(), rc(methods::plugin::plugin_list));

        // -- hash --
        table.insert("hash_create".to_string(), rc(methods::hash::hash_create));
        table.insert("hash_update".to_string(), rc(methods::hash::hash_update));
        table.insert(
            "hash_finalize".to_string(),
            rc(methods::hash::hash_finalize),
        );

        // -- cipher --
        table.insert(
            "cipher_create".to_string(),
            rc(methods::cipher::cipher_create),
        );
        table.insert(
            "cipher_update".to_string(),
            rc(methods::cipher::cipher_update),
        );
        table.insert(
            "cipher_finalize".to_string(),
            rc(methods::cipher::cipher_finalize),
        );

        // -- aead --
        table.insert("aead_create".to_string(), rc(methods::aead::aead_create));
        table.insert(
            "aead_encrypt_update".to_string(),
            rc(methods::aead::aead_encrypt_update),
        );
        table.insert(
            "aead_decrypt_update".to_string(),
            rc(methods::aead::aead_decrypt_update),
        );
        table.insert(
            "aead_finalize".to_string(),
            rc(methods::aead::aead_finalize),
        );

        // -- kdf --
        table.insert("kdf_create".to_string(), rc(methods::kdf::kdf_create));
        table.insert("kdf_derive".to_string(), rc(methods::kdf::kdf_derive));

        // -- rng --
        table.insert("rng_create".to_string(), rc(methods::rng::rng_create));
        table.insert("rng_generate".to_string(), rc(methods::rng::rng_generate));

        // -- signature --
        table.insert(
            "signature_keypair_generate".to_string(),
            rc(methods::signature::signature_keypair_generate),
        );
        table.insert(
            "signature_signer_update".to_string(),
            rc(methods::signature::signature_signer_update),
        );
        table.insert(
            "signature_signer_finalize".to_string(),
            rc(methods::signature::signature_signer_finalize),
        );
        table.insert(
            "signature_verifier_update".to_string(),
            rc(methods::signature::signature_verifier_update),
        );
        table.insert(
            "signature_verifier_finalize".to_string(),
            rc(methods::signature::signature_verifier_finalize),
        );

        // -- kem --
        table.insert(
            "kem_keypair_generate".to_string(),
            rc(methods::kem::kem_keypair_generate),
        );
        table.insert(
            "kem_encapsulate".to_string(),
            rc(methods::kem::kem_encapsulate),
        );
        table.insert(
            "kem_decapsulate".to_string(),
            rc(methods::kem::kem_decapsulate),
        );

        // -- keyfmt --
        table.insert(
            "keyfmt_parse".to_string(),
            rc(methods::keyfmt::keyfmt_parse),
        );
        table.insert(
            "keyfmt_serialize".to_string(),
            rc(methods::keyfmt::keyfmt_serialize),
        );

        // -- keystore --
        table.insert(
            "keystore_create".to_string(),
            rc(methods::keystore::keystore_create),
        );
        table.insert(
            "keystore_put_secret".to_string(),
            rc(methods::keystore::keystore_put_secret),
        );
        table.insert(
            "keystore_get_secret".to_string(),
            rc(methods::keystore::keystore_get_secret),
        );

        // -- tc (threshold computing) --
        table.insert(
            "tc_session_create".to_string(),
            rc(methods::tc::tc_session_create),
        );
        table.insert(
            "tc_session_round".to_string(),
            rc(methods::tc::tc_session_round),
        );
        table.insert(
            "tc_session_result".to_string(),
            rc(methods::tc::tc_session_result),
        );

        // -- registry --
        table.insert(
            "registry_install".to_string(),
            rc(methods::registry::registry_install),
        );
        table.insert(
            "registry_search".to_string(),
            rc(methods::registry::registry_search),
        );

        // -- audit --
        table.insert(
            "audit_subscribe".to_string(),
            rc(methods::audit::audit_subscribe),
        );

        Dispatch { table }
    }

    /// Look up the handler for `method`. Returns `None` for unknown
    /// methods — the caller produces a `MethodNotFound` error.
    pub fn get(&self, method: &str) -> Option<&Handler> {
        self.table.get(method)
    }

    /// Iterate over registered method names. Used by the `version`
    /// handler and for diagnostics.
    pub fn methods(&self) -> impl Iterator<Item = &str> {
        self.table.keys().map(String::as_str)
    }
}

impl Default for Dispatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrap a bare handler function into the type-erased `Handler` shape.
/// The handler signature is `async fn(cfm, params) -> Result<Value, RpcError>`.
fn rc<F, Fut>(f: F) -> Handler
where
    F: Fn(SharedConfium, Value) -> Fut + 'static,
    Fut: std::future::Future<Output = std::result::Result<Value, RpcError>> + 'static,
{
    Rc::new(move |cfm, params| Box::pin(f(cfm, params)))
}

/// Extract a typed parameter struct from the raw `Value`, producing an
/// `InvalidParams` RPC error on failure.
pub fn parse_params<T: serde::de::DeserializeOwned>(
    params: &Value,
) -> std::result::Result<T, RpcError> {
    serde_json::from_value(params.clone()).map_err(|e| RpcError::InvalidParams {
        detail: e.to_string(),
    })
}

/// Require that `params` is an object (or unit / missing). Returns the
/// cloned map so handlers can pull fields with `.get()`.
pub fn params_object(
    params: &Value,
) -> std::result::Result<serde_json::Map<String, Value>, RpcError> {
    match params {
        Value::Object(map) => Ok(map.clone()),
        Value::Null => Ok(serde_json::Map::new()),
        _ => Err(RpcError::InvalidParams {
            detail: "expected an object".to_string(),
        }),
    }
}

/// Pull a string field from the params map, erroring if missing.
pub fn require_str(
    map: &serde_json::Map<String, Value>,
    key: &str,
) -> std::result::Result<String, RpcError> {
    map.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| RpcError::InvalidParams {
            detail: format!("missing or non-string field '{key}'"),
        })
}

/// Pull a byte field from the params map. Accepts a JSON string and
/// decodes it as base64, or a JSON array of numbers.
pub fn require_bytes(
    map: &serde_json::Map<String, Value>,
    key: &str,
) -> std::result::Result<Vec<u8>, RpcError> {
    let v = map.get(key).ok_or_else(|| RpcError::InvalidParams {
        detail: format!("missing field '{key}'"),
    })?;
    match v {
        Value::String(s) => decode_base64(s).map_err(|e| RpcError::InvalidParams {
            detail: format!("field '{key}' is not valid base64: {e}"),
        }),
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for (i, n) in arr.iter().enumerate() {
                let b = n.as_u64().ok_or_else(|| RpcError::InvalidParams {
                    detail: format!("field '{key}[{i}]' is not a number"),
                })?;
                if b > 255 {
                    return Err(RpcError::InvalidParams {
                        detail: format!("field '{key}[{i}]' = {b} exceeds 255"),
                    });
                }
                out.push(b as u8);
            }
            Ok(out)
        }
        _ => Err(RpcError::InvalidParams {
            detail: format!("field '{key}' must be a base64 string or byte array"),
        }),
    }
}

/// Standard base64 decoder (RFC 4648, no padding required). Kept
/// inline to avoid pulling a base64 crate into the workspace.
fn decode_base64(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for (i, c) in s.chars().enumerate() {
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return Err(format!("invalid base64 char at index {i}")),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_roundtrip() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("Zm9vYmFy").unwrap(), b"foobar");
        // URL-safe variant
        assert_eq!(decode_base64("-_8=").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn dispatch_registers_all_methods() {
        let d = Dispatch::new();
        let names: Vec<&str> = d.methods().collect();
        assert!(names.contains(&"version"));
        assert!(names.contains(&"shutdown"));
        assert!(names.contains(&"plugin_load"));
        assert!(names.contains(&"hash_create"));
        assert!(names.contains(&"audit_subscribe"));
    }
}
