//! Connected WebSocket transport and the registry kind for
//! `ws` / `wss`.
//!
//! [`WsTransport`] wraps a [`tungstenite::WebSocket`] and implements
//! [`confium_net::Transport`]. Each `send` is written as one
//! WebSocket binary frame; each `recv` reads one binary frame. The
//! WebSocket protocol itself preserves message boundaries, so — unlike
//! [`confium_net_tcp`] — no length-prefix layer is needed.
//!
//! The transport is generic over the underlying stream so the same
//! type serves both dial-out clients (whose stream is
//! `MaybeTlsStream<TcpStream>` — plain for `ws://`, TLS for `wss://`)
//! and accepted servers (whose stream is bare `TcpStream`). A sealed
//! [`WsInner`] trait abstracts the two behind a single
//! `Box<dyn WsInner>` so callers see one concrete `WsTransport` type
//! regardless of how the connection was established.

use std::net::TcpStream;

use tungstenite::Message;
use tungstenite::WebSocket;
use tungstenite::client::IntoClientRequest;
use tungstenite::stream::MaybeTlsStream;
use url::Url;

use confium_net::Listener;
use confium_net::Result;
use confium_net::Transport;
use confium_net::error::ClosedSnafu;
use confium_net::error::MalformedUrlSnafu;
use confium_net::registry::TransportKind;

// ---- sealed stream abstraction --------------------------------------

/// Private trait that the two WebSocket stream shapes (`MaybeTlsStream`
/// for dial-out, bare `TcpStream` for accepted) satisfy. Sealed so
/// downstream crates cannot add new impls and accidentally break the
/// `Box<dyn WsInner>` vtable contract.
mod private {
    use std::net::TcpStream;

    use tungstenite::stream::MaybeTlsStream;

    pub trait Sealed {}

    impl Sealed for MaybeTlsStream<TcpStream> {}
    impl Sealed for TcpStream {}
}

/// Anything a [`tungstenite::WebSocket`] can sit on top of in this
/// crate. Trait-sealed to `MaybeTlsStream<TcpStream>` (client,
/// `ws://` or `wss://`) and bare `TcpStream` (server, `ws://`).
pub(crate) trait WsStream: std::io::Read + std::io::Write + private::Sealed + Send {}

impl WsStream for MaybeTlsStream<TcpStream> {}
impl WsStream for TcpStream {}

/// Type-erased WebSocket handle so [`WsTransport`] is one concrete
/// type regardless of whether the underlying stream is TLS-wrapped.
pub(crate) trait WsInner: Send {
    fn send(&mut self, msg: Message) -> tungstenite::Result<()>;
    fn read(&mut self) -> tungstenite::Result<Message>;
    fn close(&mut self) -> tungstenite::Result<()>;
}

impl<S: WsStream> WsInner for WebSocket<S> {
    fn send(&mut self, msg: Message) -> tungstenite::Result<()> {
        WebSocket::send(self, msg)
    }

    fn read(&mut self) -> tungstenite::Result<Message> {
        WebSocket::read(self)
    }

    fn close(&mut self) -> tungstenite::Result<()> {
        WebSocket::send(self, Message::Close(None))
    }
}

// ---- connected transport -------------------------------------------

/// Connected WebSocket transport. Owns the underlying
/// [`tungstenite::WebSocket`]; `close` sends a WebSocket Close frame
/// so the peer observes a clean end-of-stream.
pub struct WsTransport {
    inner: Option<Box<dyn WsInner>>,
}

impl WsTransport {
    /// Wrap an already-handshaked client WebSocket (used by
    /// [`WsTransportKind::connect`]).
    fn from_client<S: WsStream + 'static>(ws: WebSocket<S>) -> Self {
        Self {
            inner: Some(Box::new(ws)),
        }
    }

    /// Wrap an already-handshaked accepted WebSocket (used by
    /// [`crate::listener::WsListener`] for accepted peers).
    pub(crate) fn from_server<S: WsStream + 'static>(ws: WebSocket<S>) -> Self {
        Self {
            inner: Some(Box::new(ws)),
        }
    }

    /// Dial a peer at `url`, performing the WebSocket handshake. The
    /// scheme in `url` (`ws` or `wss`) selects plain TCP or TLS via
    /// rustls.
    pub(crate) fn connect(url: &Url) -> tungstenite::Result<Self> {
        // `IntoClientRequest` for `&str` / `String` requires the
        // `url` feature on tungstenite. Build the request from the
        // canonical URL string so the Host header and request-target
        // are populated correctly.
        let req = url.as_str().into_client_request()?;
        let (ws, _resp) = tungstenite::connect(req)?;
        Ok(Self::from_client(ws))
    }
}

impl Transport for WsTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        let ws = match &mut self.inner {
            Some(w) => w,
            None => return ClosedSnafu.fail(),
        };
        // Binary frames carry arbitrary bytes; tungstenite handles
        // fragmentation for large payloads transparently.
        ws.send(Message::binary(data.to_vec()))
            .map_err(ws_to_closed)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let ws = match &mut self.inner {
            Some(w) => w,
            None => return ClosedSnafu.fail(),
        };
        loop {
            let msg = match ws.read() {
                Ok(m) => m,
                Err(e) => return Err(ws_to_closed(e)),
            };
            match msg {
                // Binary is the payload-bearing message type. Deliver
                // as much as fits in the caller's buffer; the
                // remainder is dropped, matching the inproc/tcp
                // transports' "fill what you can" semantics for
                // undersized buffers.
                Message::Binary(data) => {
                    let n = std::cmp::min(data.len(), buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok(n);
                }
                // Close frame: the peer ended the session cleanly.
                Message::Close(_) => return ClosedSnafu.fail(),
                // Pings are answered by tungstenite automatically with
                // a matching pong (the library handles the keep-alive
                // half of the protocol); pongs arriving here are not
                // application payload, so skip them.
                Message::Pong(_) | Message::Ping(_) => continue,
                // Text frames are not used by Confium transports;
                // treat their UTF-8 bytes as binary data so a peer
                // that sends text anyway still works.
                Message::Text(t) => {
                    let bytes = t.as_bytes();
                    let n = std::cmp::min(bytes.len(), buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    return Ok(n);
                }
                // Raw frames are never surfaced by tungstenite's
                // `read()` — the library assembles complete messages.
                // If we somehow see one, hand its payload over.
                Message::Frame(_) => continue,
            }
        }
    }

    fn close(&mut self) -> Result<()> {
        if let Some(mut ws) = self.inner.take() {
            // Send a Close frame so the peer's read observes a clean
            // end-of-stream rather than a TCP RST. Best-effort: a
            // peer that already went away surfaces an error here that
            // we swallow.
            ws.close().ok();
        }
        Ok(())
    }
}

impl Drop for WsTransport {
    fn drop(&mut self) {
        if let Some(mut ws) = self.inner.take() {
            ws.close().ok();
        }
    }
}

// ---- registry kind -------------------------------------------------

/// Registry kind for `ws`, `wss`.
pub struct WsTransportKind;

impl TransportKind for WsTransportKind {
    fn schemes(&self) -> &'static [&'static str] {
        &["ws", "wss"]
    }

    fn connect(&self, url: &Url) -> Result<Box<dyn Transport>> {
        let scheme = url.scheme();
        host_check(url, scheme)?;
        match WsTransport::connect(url) {
            Ok(t) => Ok(Box::new(t)),
            Err(_) => MalformedUrlSnafu {
                scheme,
                url: url.to_string(),
                reason: "could not connect to peer",
            }
            .fail(),
        }
    }

    fn listen(&self, url: &Url) -> Result<Box<dyn Listener>> {
        let scheme = url.scheme();
        let (host, port) = host_port(url, scheme)?;
        match crate::listener::WsListener::bind(scheme, host, port) {
            Ok(l) => Ok(Box::new(l)),
            Err(_) => MalformedUrlSnafu {
                scheme,
                url: url.to_string(),
                reason: "could not bind to address",
            }
            .fail(),
        }
    }
}

// ---- shared helpers ------------------------------------------------

/// Extract the `(host, port)` pair from a `ws://` / `wss://` URL. The
/// port is mandatory (no implicit 80/443 defaulting — Confium URLs
/// always spell the port out, mirroring the `tcp://` contract).
pub(crate) fn host_port<'a>(url: &'a Url, scheme: &str) -> Result<(&'a str, u16)> {
    host_check(url, scheme)?;
    let port = match url.port() {
        Some(p) => p,
        None => {
            return MalformedUrlSnafu {
                scheme,
                url: url.to_string(),
                reason: "missing port (use ws://<host>:<port>)",
            }
            .fail();
        }
    };
    Ok((url.host_str().unwrap_or(""), port))
}

/// Reject URLs with no host.
fn host_check(url: &Url, scheme: &str) -> Result<()> {
    if url.host_str().map(|h| h.is_empty()).unwrap_or(true) {
        return MalformedUrlSnafu {
            scheme,
            url: url.to_string(),
            reason: "missing host (use ws://<host>:<port>)",
        }
        .fail();
    }
    Ok(())
}

/// Map a [`tungstenite::Error`] to a [`confium_net::Error`]. The
/// confium-net error type does not today carry an arbitrary source,
/// so connection / read / write failures are reported as `Closed` —
/// the transport is unusable after a WebSocket error, matching how
/// the inproc/tcp transports report a broken channel.
pub(crate) fn ws_to_closed(_: tungstenite::Error) -> confium_net::Error {
    ClosedSnafu.build()
}

/// Map an [`std::io::Error`] (e.g. from `accept` on the underlying
/// TCP socket before the WebSocket handshake completes) to a
/// [`confium_net::Error`]. Mirrors [`ws_to_closed`] — the transport
/// is unusable after an I/O failure.
pub(crate) fn io_to_closed(_: std::io::Error) -> confium_net::Error {
    ClosedSnafu.build()
}

/// Map a [`tungstenite::HandshakeError`] (raised when the server-side
/// `accept` or client-side `connect` handshake fails) to a
/// [`confium_net::Error`]. Same "report as Closed" rationale as the
/// other mappers: the resulting transport cannot carry bytes.
pub(crate) fn handshake_to_closed<R: tungstenite::handshake::HandshakeRole>(
    _e: tungstenite::HandshakeError<R>,
) -> confium_net::Error {
    ClosedSnafu.build()
}

// Silence an unused-import lint when this file is read in isolation
// during type-checking of the trait object's vtable.
#[allow(dead_code)]
fn _assert_tcp_stream_send() {
    fn needs_send<T: Send>() {}
    needs_send::<TcpStream>();
}
