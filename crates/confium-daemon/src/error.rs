//! Errors surfaced by the confiumd JSON-RPC daemon.
//!
//! Daemon errors fall into two layers:
//! - [`RpcError`] — JSON-RPC protocol errors, serialized into a
//!   `"error"` object on the wire (see `protocol.rs`).
//! - [`DaemonError`] — transport / lifecycle failures that bubble up to
//!   the listen loop and usually terminate the process.

use snafu::Snafu;

/// JSON-RPC error codes as defined by the spec, plus the
/// Confium-specific range (−32000 to −32099) for server errors.
///
/// Spec: <https://www.jsonrpc.org/specification#error_object>
pub mod code {
    /// Invalid JSON was received by the server.
    pub const PARSE_ERROR: i32 = -32700;
    /// The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i32 = -32600;
    /// The method does not exist / is not available.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid method parameter(s).
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i32 = -32603;
    /// Generic server error (Confium-specific range start).
    pub const SERVER_ERROR: i32 = -32000;
    /// A Confium engine operation returned an error.
    pub const ENGINE_ERROR: i32 = -32001;
}

/// An error that can be serialized into a JSON-RPC `"error"` object.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum RpcError {
    /// The requested method is not registered in the dispatch table.
    #[snafu(display("Method not found: {method}"))]
    MethodNotFound { method: String },

    /// The params object was missing required fields or had the wrong
    /// shape for the method.
    #[snafu(display("Invalid params: {detail}"))]
    InvalidParams { detail: String },

    /// The Confium engine returned an error. The message is the
    /// engine's `Display` string; the numeric sub-code (if the caller
    /// cares) is logged separately.
    #[snafu(display("Engine error: {message}"))]
    Engine { message: String },

    /// Catch-all for unexpected internal failures.
    #[snafu(display("Internal error: {detail}"))]
    Internal { detail: String },
}

impl RpcError {
    /// Map this error to the JSON-RPC integer code it should be
    /// reported under.
    pub fn code(&self) -> i32 {
        match self {
            RpcError::MethodNotFound { .. } => code::METHOD_NOT_FOUND,
            RpcError::InvalidParams { .. } => code::INVALID_PARAMS,
            RpcError::Engine { .. } => code::ENGINE_ERROR,
            RpcError::Internal { .. } => code::INTERNAL_ERROR,
        }
    }
}

/// Transport / lifecycle errors that are not reported to the client as
/// a JSON-RPC error but instead cause the listener or connection loop
/// to abort.
#[derive(Debug, Snafu)]
pub enum DaemonError {
    #[snafu(display("I/O error: {source}"))]
    Io { source: std::io::Error },

    #[snafu(display("Failed to serialize response: {source}"))]
    Serialize { source: serde_json::Error },

    #[snafu(display("Failed to bind listener: {source}"))]
    Bind { source: std::io::Error },

    #[snafu(display("Shutdown signaled"))]
    Shutdown,
}

pub type Result<T> = std::result::Result<T, DaemonError>;

impl From<std::io::Error> for DaemonError {
    fn from(source: std::io::Error) -> Self {
        DaemonError::Io { source }
    }
}

impl From<serde_json::Error> for DaemonError {
    fn from(source: serde_json::Error) -> Self {
        DaemonError::Serialize { source }
    }
}
