//! JSON-RPC server loop.
//!
//! Accepts connections on a [`tokio::net::TcpListener`] or Unix socket
//! and serves each with a task that reads length-prefixed JSON-RPC
//! messages, dispatches them, and writes responses.
//!
//! Framing: each message is a 4-byte big-endian length prefix followed
//! by that many bytes of UTF-8 JSON. This is the same framing used by
//! LSP / DAP and most production JSON-RPC daemons; it avoids the
//! ambiguity of newline-delimited JSON when payloads contain embedded
//! newlines.
//!
//! Threading: the Confium engine holds `Rc<dyn Any>` plugin interfaces,
//! which makes it `!Send`. The server therefore runs on a single
//! [`tokio::task::LocalSet`] and keeps the engine behind
//! `Rc<RefCell<Confium>>`. Connections are driven concurrently by the
//! LocalSet's cooperative scheduler; Confium access is serialized by
//! the `RefCell` borrow. This is the right shape for a skeleton — the
//! engine is single-threaded by construction (the C FFI assumes it),
//! and moving to a multi-threaded actor model is a later optimization.

use std::cell::RefCell;
use std::rc::Rc;

use confium_core::Confium;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;
use tokio_util::sync::CancellationToken;

use crate::dispatch::Dispatch;
use crate::error::{self, DaemonError, RpcError};
use crate::protocol::{RpcRequest, RpcResponse};

/// Type alias for the shared engine handle. `Rc<RefCell<...>>` because
/// `Confium` is `!Send` (plugin interfaces are `Rc<dyn Any>`).
pub type SharedConfium = Rc<RefCell<Confium>>;

/// The daemon's shared state: the engine, the dispatch table, and a
/// shutdown signal.
pub struct Server {
    /// The single Confium instance owned by the daemon. All method
    /// handlers dispatch against this.
    pub cfm: SharedConfium,

    /// Method-name → handler table.
    pub dispatch: Dispatch,

    /// Cancellation token: set when `shutdown` is called or the process
    /// receives a signal. Stops the accept loop and drains.
    pub cancel: CancellationToken,
}

impl Server {
    /// Construct a server with a fresh Confium (audit logger resolved
    /// from the environment) and the default dispatch table.
    pub fn new() -> Self {
        Server {
            cfm: Rc::new(RefCell::new(Confium::new())),
            dispatch: Dispatch::new(),
            cancel: CancellationToken::new(),
        }
    }

    /// Construct a server with an explicit Confium (used by tests that
    /// want the audit logger disabled).
    pub fn with_confium(cfm: Confium) -> Self {
        Server {
            cfm: Rc::new(RefCell::new(cfm)),
            dispatch: Dispatch::new(),
            cancel: CancellationToken::new(),
        }
    }

    /// Run the accept loop on a TCP listener until shutdown. Must be
    /// called from within a [`LocalSet`] — see [`Server::run_tcp`].
    pub async fn serve_tcp(self: Rc<Self>, listener: TcpListener) -> error::Result<()> {
        let shutdown = self.cancel.clone();
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                accept = listener.accept() => {
                    let (stream, _peer) = accept?;
                    let server = Rc::clone(&self);
                    // spawn_local so the !Send Confium stays on this
                    // thread's LocalSet.
                    tokio::task::spawn_local(async move {
                        let _ = server.handle_tcp(stream).await;
                    });
                }
            }
        }
        Ok(())
    }

    /// Run the accept loop on a Unix socket listener until shutdown.
    pub async fn serve_unix(
        self: Rc<Self>,
        listener: tokio::net::UnixListener,
    ) -> error::Result<()> {
        let shutdown = self.cancel.clone();
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                accept = listener.accept() => {
                    let (stream, _peer) = accept?;
                    let server = Rc::clone(&self);
                    tokio::task::spawn_local(async move {
                        let _ = server.handle_unix(stream).await;
                    });
                }
            }
        }
        Ok(())
    }

    /// Drive a TCP listener inside a [`LocalSet`] until shutdown. This
    /// is the convenience entry point for `main` and tests: it creates
    /// the LocalSet, enters it, and runs the accept loop.
    pub async fn run_tcp(self: Rc<Self>, listener: TcpListener) -> error::Result<()> {
        let local = LocalSet::new();
        local.run_until(self.serve_tcp(listener)).await
    }

    /// Drive a Unix listener inside a [`LocalSet`] until shutdown.
    pub async fn run_unix(self: Rc<Self>, listener: tokio::net::UnixListener) -> error::Result<()> {
        let local = LocalSet::new();
        local.run_until(self.serve_unix(listener)).await
    }

    /// Handle a single TCP connection: read length-prefixed requests,
    /// dispatch, write responses. Returns when the peer closes the
    /// connection or an unrecoverable I/O error occurs.
    async fn handle_tcp(self: Rc<Self>, stream: tokio::net::TcpStream) -> error::Result<()> {
        let (mut read, mut write) = tokio::io::split(stream);
        Self::drive_connection(&self, &mut read, &mut write).await
    }

    /// Handle a single Unix socket connection.
    async fn handle_unix(self: Rc<Self>, stream: tokio::net::UnixStream) -> error::Result<()> {
        let (mut read, mut write) = tokio::io::split(stream);
        Self::drive_connection(&self, &mut read, &mut write).await
    }

    /// Shared connection loop: read a message, dispatch, write reply.
    /// Generic over the split read/write halves.
    async fn drive_connection<R, W>(
        self: &Rc<Self>,
        read: &mut R,
        write: &mut W,
    ) -> error::Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        loop {
            let msg = match read_length_prefixed(read).await? {
                Some(m) => m,
                None => return Ok(()), // EOF
            };
            let response = self.process(&msg).await;
            if let Some(resp) = response {
                let bytes = serde_json::to_vec(&resp)?;
                write_length_prefixed(write, &bytes).await?;
            }
            if self.cancel.is_cancelled() {
                break;
            }
        }
        Ok(())
    }

    /// Parse a raw JSON message, dispatch, and produce the response
    /// (or `None` for notifications).
    async fn process(self: &Rc<Self>, raw: &[u8]) -> Option<RpcResponse> {
        let req: RpcRequest = match serde_json::from_slice(raw) {
            Ok(r) => r,
            Err(e) => {
                return Some(RpcResponse::err(
                    Value::Null,
                    RpcError::InvalidParams {
                        detail: format!("parse error: {e}"),
                    },
                ));
            }
        };

        if !req.version_ok() {
            return Some(RpcResponse::err(
                req.id.unwrap_or(Value::Null),
                RpcError::InvalidParams {
                    detail: "jsonrpc must be \"2.0\"".to_string(),
                },
            ));
        }

        // Special-case `shutdown`: reply then cancel the accept loop.
        let is_shutdown = req.method == "shutdown";

        let handler = match self.dispatch.get(&req.method) {
            Some(h) => h,
            None => {
                return if req.is_notification() {
                    None
                } else {
                    Some(RpcResponse::err(
                        req.id.unwrap_or(Value::Null),
                        RpcError::MethodNotFound {
                            method: req.method.clone(),
                        },
                    ))
                };
            }
        };

        let result = handler(Rc::clone(&self.cfm), req.params.clone()).await;

        if is_shutdown {
            self.cancel.cancel();
        }

        if req.is_notification() {
            return None;
        }

        let id = req.id.unwrap_or(Value::Null);
        Some(match result {
            Ok(value) => RpcResponse::ok(id, value),
            Err(err) => RpcResponse::err(id, err),
        })
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

// --- length-prefixed framing -------------------------------------------

/// Read one length-prefixed message. Returns `None` on clean EOF.
///
/// Reads 4 bytes (big-endian u32 length), then that many bytes of
/// payload.
async fn read_length_prefixed<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> error::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    // A clean EOF before any bytes means the peer closed; a partial
    // read is an error.
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(DaemonError::Io { source: e }),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    // Cap the message size to avoid a hostile peer forcing a huge
    // allocation. 16 MiB is well above any legitimate JSON-RPC payload.
    const MAX_MESSAGE: usize = 16 * 1024 * 1024;
    if len > MAX_MESSAGE {
        return Err(DaemonError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("message length {len} exceeds {MAX_MESSAGE}"),
            ),
        });
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Write a length-prefixed message.
async fn write_length_prefixed<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> error::Result<()> {
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use confium_core::audit::AuditLogger;

    fn server() -> Server {
        Server::with_confium(Confium::new_with_audit(AuditLogger::disabled()))
    }

    #[tokio::test]
    async fn process_unknown_method_returns_method_not_found() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let s = Rc::new(server());
                let raw = br#"{"jsonrpc":"2.0","id":1,"method":"does_not_exist","params":{}}"#;
                let resp = s.process(raw).await.unwrap();
                let serialized = serde_json::to_value(&resp).unwrap();
                assert_eq!(
                    serialized["error"]["code"],
                    RpcError::MethodNotFound { method: "".into() }.code()
                );
            })
            .await;
    }

    #[tokio::test]
    async fn process_version_returns_pkg_version() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let s = Rc::new(server());
                let raw = br#"{"jsonrpc":"2.0","id":1,"method":"version","params":{}}"#;
                let resp = s.process(raw).await.unwrap();
                let serialized = serde_json::to_value(&resp).unwrap();
                assert_eq!(serialized["result"]["version"], env!("CARGO_PKG_VERSION"));
            })
            .await;
    }

    #[tokio::test]
    async fn process_bad_json_returns_parse_error() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let s = Rc::new(server());
                let resp = s.process(b"not json").await.unwrap();
                let serialized = serde_json::to_value(&resp).unwrap();
                assert!(
                    serialized["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("parse error")
                );
            })
            .await;
    }

    #[tokio::test]
    async fn process_notification_returns_none() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let s = Rc::new(server());
                // No "id" → notification. The server must not reply.
                let raw = br#"{"jsonrpc":"2.0","method":"version","params":{}}"#;
                let resp = s.process(raw).await;
                assert!(resp.is_none());
            })
            .await;
    }

    #[tokio::test]
    async fn shutdown_triggers_cancellation() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let s = Rc::new(server());
                let raw = br#"{"jsonrpc":"2.0","id":1,"method":"shutdown","params":{}}"#;
                let _ = s.process(raw).await;
                assert!(s.cancel.is_cancelled());
            })
            .await;
    }

    #[tokio::test]
    async fn length_prefixed_roundtrip() {
        // Write then read a length-prefixed message through an
        // in-memory pipe.
        let payload = br#"{"jsonrpc":"2.0","id":1,"method":"version"}"#;
        let mut buf = Vec::new();
        write_length_prefixed(&mut buf, payload).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let msg = read_length_prefixed(&mut cursor).await.unwrap().unwrap();
        assert_eq!(msg, payload);
    }
}
