//! Meta methods: `version`, `shutdown`.
//!
//! `version` returns the daemon's package version (same as
//! `confium-core`'s). `shutdown` signals the listen loop to stop
//! accepting new connections and exit after in-flight requests drain.

use serde_json::{Value, json};

use crate::error::RpcError;
use crate::server::SharedConfium;

/// `version()` → `{"version": "0.3.0", "major": 0, "minor": 3, "patch": 0}`
///
/// The version string is the daemon's own `CARGO_PKG_VERSION`, which is
/// kept in sync with the workspace version via `version.workspace =
/// true`.
pub async fn version(_cfm: SharedConfium, _params: Value) -> std::result::Result<Value, RpcError> {
    let v = env!("CARGO_PKG_VERSION");
    let parts: Vec<u32> = v
        .split('.')
        .map(|s| s.parse::<u32>().unwrap_or(0))
        .collect();
    Ok(json!({
        "version": v,
        "major": parts.first().copied().unwrap_or(0),
        "minor": parts.get(1).copied().unwrap_or(0),
        "patch": parts.get(2).copied().unwrap_or(0),
    }))
}

/// `shutdown()` → `{"ok": true}`
///
/// The handler itself only acknowledges the request. The actual
/// shutdown is triggered by the connection layer watching for this
/// method name — when it sees `shutdown`, it initiates graceful
/// teardown after replying.
pub async fn shutdown(_cfm: SharedConfium, _params: Value) -> std::result::Result<Value, RpcError> {
    Ok(json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_confium;

    #[tokio::test]
    async fn version_returns_pkg_version() {
        let result = version(test_confium(), json!({})).await.unwrap();
        let obj = result.as_object().unwrap();
        assert_eq!(
            obj.get("version").unwrap().as_str().unwrap(),
            env!("CARGO_PKG_VERSION")
        );
        assert!(obj.get("major").unwrap().is_u64());
    }

    #[tokio::test]
    async fn shutdown_acknowledges() {
        let result = shutdown(test_confium(), json!({})).await.unwrap();
        assert_eq!(result, json!({ "ok": true }));
    }
}
