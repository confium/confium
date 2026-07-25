//! Audit subscription methods.
//!
//! `audit_subscribe` registers the caller's connection as a recipient
//! of audit events. The server pushes [`AuditNotification`] messages
//! to subscribed connections whenever the core audit logger emits an
//! event.
//!
//! The skeleton returns `{"subscribed": true}` and relies on the
//! server loop to route notifications to the connection. A real
//! implementation would install a broadcast channel receiver on the
//! daemon-wide audit sink.

use serde_json::{Value, json};

use crate::error::RpcError;
use crate::server::SharedConfium;

/// `audit_subscribe({})` → `{"subscribed": true}`
///
/// No params today. The server loop inspects the result and, on
/// success, marks the connection as subscribed so subsequent audit
/// events are forwarded as JSON-RPC notifications.
pub async fn audit_subscribe(
    _cfm: SharedConfium,
    _params: Value,
) -> std::result::Result<Value, RpcError> {
    Ok(json!({ "subscribed": true }))
}
