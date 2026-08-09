//! JSON-RPC 2.0 wire types.
//!
//! Each method handler receives an [`RpcRequest`] (params extracted by
//! the caller into a typed `Value`) and returns either an
//! [`RpcResponse::Ok`] with a JSON result or [`RpcResponse::Err`] with
//! a structured [`crate::error::RpcError`].
//!
//! Spec: <https://www.jsonrpc.org/specification>
//!
//! The transport framing (length-prefixed JSON, newline-delimited JSON,
//! etc.) is layered on top by the server loop — this module only
//! concerns itself with the payload shape.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::RpcError;

/// JSON-RPC 2.0 request object.
///
/// `params` is left as `Value`; each handler parses it into its own
/// concrete shape. A notification is a request with `id == None`.
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    /// Protocol version. Must be `"2.0"`; other values are rejected at
    /// the transport layer before the handler runs.
    pub jsonrpc: String,

    /// Method name. Maps into the dispatch table.
    pub method: String,

    /// Method parameters. Object form (`{"foo": 1}`) is preferred for
    /// clarity, but positional arrays are also accepted by the spec.
    #[serde(default)]
    pub params: Value,

    /// `None` means the request is a notification — the server replies
    /// with no body. Notifications may not include an error reply.
    #[serde(default, deserialize_with = "deserialize_opt_id")]
    pub id: Option<Value>,
}

/// Allow `id` to be a number, string, or null. `null` is treated as
/// "no id" (notification) per the spec.
fn deserialize_opt_id<'de, D>(deserializer: D) -> std::result::Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    Ok(if v.is_null() { None } else { Some(v) })
}

impl RpcRequest {
    /// `true` if this is a notification (no id, no response expected).
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Strictly check the `jsonrpc` field is `"2.0"`.
    pub fn version_ok(&self) -> bool {
        self.jsonrpc == "2.0"
    }
}

/// JSON-RPC 2.0 response object.
///
/// Only the Ok / Err variants cross the wire; `InternalError` is a
/// transport-layer failure that is converted into a serialized
/// `RpcResponse::Err` before reaching the client.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RpcResponse {
    /// Successful response.
    Ok(RpcSuccess),
    /// Error response.
    Err(RpcErrorBody),
}

#[derive(Debug, Serialize)]
pub struct RpcSuccess {
    pub jsonrpc: &'static str,
    pub id: Value,
    pub result: Value,
}

#[derive(Debug, Serialize)]
pub struct RpcErrorBody {
    pub jsonrpc: &'static str,
    pub id: Value,
    pub error: RpcErrorPayload,
}

/// The body of a JSON-RPC error reply. Serializes as
/// `{"code": ..., "message": "..."}` per the spec.
#[derive(Debug, Serialize)]
pub struct RpcErrorPayload {
    pub code: i32,
    pub message: String,
}

impl RpcResponse {
    /// Build a success response carrying `result` as the JSON value.
    /// `id` is the value from the matching request.
    pub fn ok(id: Value, result: Value) -> Self {
        RpcResponse::Ok(RpcSuccess {
            jsonrpc: "2.0",
            id,
            result,
        })
    }

    /// Build an error response carrying the given [`RpcError`].
    /// `id` is the value from the matching request (or `Value::Null`
    /// if the request was unparsable).
    pub fn err(id: Value, err: RpcError) -> Self {
        RpcResponse::Err(RpcErrorBody {
            jsonrpc: "2.0",
            id,
            error: RpcErrorPayload {
                code: err.code(),
                message: err.to_string(),
            },
        })
    }
}

/// Notification pushed to audit subscribers. The wire shape mirrors
/// `audit::event::AuditEvent::to_json` so subscribers can read both
/// `audit` messages and the daemon's own [`RpcRequest`] messages from
/// the same stream.
#[derive(Debug, Serialize)]
pub struct AuditNotification<'a> {
    pub jsonrpc: &'static str,
    pub method: &'static str,
    pub params: AuditParams<'a>,
}

#[derive(Debug, Serialize)]
pub struct AuditParams<'a> {
    pub ts: &'a str,
    pub event: &'a str,
    /// Free-form event payload. The exact keys depend on the variant —
    /// see [`crate::methods::audit::AuditEvent`] for the canonical shape.
    #[serde(flatten)]
    pub fields: &'a serde_json::Map<String, Value>,
}

impl<'a> AuditNotification<'a> {
    /// Build a notification from a serialized audit event. The caller
    /// has already produced the JSONL record (one line, no trailing
    /// newline); we re-wrap it into the `params` envelope.
    pub fn from_jsonl(
        ts: &'a str,
        event: &'a str,
        fields: &'a serde_json::Map<String, Value>,
    ) -> Self {
        AuditNotification {
            jsonrpc: "2.0",
            method: "audit",
            params: AuditParams { ts, event, fields },
        }
    }
}
