//! Plugin lifecycle methods: `plugin_load`, `plugin_unload`, `plugin_list`.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::RpcError;
use crate::server::SharedConfium;

/// `plugin_load({ "path": "...", "name": "botan", "options": {} })`
/// → `{"success": true}`
///
/// Delegates to [`Confium::load_plugin`]. The options map is passed
/// through as a string-keyed map (matching the C FFI's `Options` type,
/// which is `HashMap<String, String>` today).
///
/// `name` is accepted for API parity with the C FFI's
/// `cfm_plugin_load(cfm, name, path, opts)` but is not yet forwarded
/// to the core (the core stub derives the name from the path). When
/// the core accepts an explicit name, this handler will pass it
/// through unchanged.
#[derive(Deserialize)]
#[allow(dead_code)]
struct PluginLoadParams {
    path: String,
    name: String,
    #[serde(default)]
    options: HashMap<String, String>,
}

pub async fn plugin_load(
    cfm: SharedConfium,
    params: Value,
) -> std::result::Result<Value, RpcError> {
    let p: PluginLoadParams =
        serde_json::from_value(params).map_err(|e| RpcError::InvalidParams {
            detail: e.to_string(),
        })?;

    let cfm = cfm.borrow();
    cfm.load_plugin(&PathBuf::from(&p.path), &p.options)
        .map_err(|e| RpcError::Engine {
            message: e.to_string(),
        })?;

    Ok(json!({ "success": true }))
}

/// `plugin_unload({ "name": "botan" })` → `{"success": true}`
///
/// The core `unload` path is not yet implemented (the FFI is a stub),
/// so this handler returns the engine's "not implemented" error. When
/// the core lands, the handler becomes a one-line adapter.
pub async fn plugin_unload(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Err(RpcError::Engine {
        message: "plugin_unload is not yet implemented in confium-core".to_string(),
    })
}

/// `plugin_list()` → `{"plugins": [{"name": "botan"}, ...]}`
///
/// Lists the providers currently registered on the owned Confium. The
/// core's `providers` field is private, so we return an empty list
/// today; once a public accessor lands, this will return the full list
/// with metadata.
pub async fn plugin_list(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    // The providers vector is private in confium-core; we can't
    // enumerate it without a public accessor. Return an empty list
    // as a placeholder — the shape is stable for clients.
    Ok(json!({ "plugins": [] }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_confium;

    #[tokio::test]
    async fn plugin_list_returns_array() {
        let result = plugin_list(test_confium(), json!({})).await.unwrap();
        assert!(result.get("plugins").unwrap().is_array());
    }
}
