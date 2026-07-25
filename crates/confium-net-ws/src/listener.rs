//! Listening endpoint for `ws://` URLs.
//!
//! [`WsListener`] wraps [`std::net::TcpListener`] and implements
//! [`confium_net::Listener`]. Each [`accept`](confium_net::Listener::accept)
//! blocks for an inbound TCP connection, then performs the WebSocket
//! server-side handshake ([`tungstenite::accept`]) to upgrade it,
//! returning a [`crate::WsTransport`] wrapping the upgraded
//! [`tungstenite::WebSocket`].
//!
//! Server-side TLS for `wss://` is not implemented here; a
//! TLS-terminating reverse proxy (nginx, Caddy, etc.) in front of a
//! plain `ws://` listener is the recommended deployment.

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpListener as StdTcpListener;

use confium_net::Listener;
use confium_net::Result;
use confium_net::Transport;
use confium_net::error::ClosedSnafu;

use crate::WsTransport;

/// Listening endpoint for inbound WebSocket connections.
///
/// Holding this alive keeps the bound TCP socket open; dropping it
/// closes the socket (the OS releases the port).
pub struct WsListener {
    inner: Option<StdTcpListener>,
}

impl WsListener {
    /// Bind a new listener at `host:port`. The address family is
    /// always IPv4 (matching the loopback test pattern used by
    /// `confium-net-tcp`); pass `0.0.0.0` for any interface or
    /// `127.0.0.1` for loopback-only. Passing port `0` requests an
    /// ephemeral port from the OS; the caller can read the assigned
    /// port back via [`local_addr`](Self::local_addr).
    pub fn bind(scheme: &str, host: &str, port: u16) -> std::io::Result<Self> {
        // Both `ws` and `wss` URLs may be passed here. For `wss://`
        // we expect a reverse proxy to terminate TLS upstream and
        // forward plain WebSocket frames; the listener itself always
        // binds a plain TCP socket.
        let _ = scheme;

        // Resolve `host` as an IPv4 literal. The loopback test path
        // uses `127.0.0.1`; `0.0.0.0` is the all-interfaces
        // wildcard. DNS names are not supported at the listener —
        // production deployments front the listener with a proxy
        // that handles name-based routing.
        let ip: Ipv4Addr = host.parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IPv4 bind address '{host}'"),
            )
        })?;
        let listener = StdTcpListener::bind(SocketAddr::new(std::net::IpAddr::V4(ip), port))?;
        listener.set_nonblocking(false).ok();
        Ok(Self {
            inner: Some(listener),
        })
    }

    /// The locally-bound socket address. Useful for reading back the
    /// OS-assigned ephemeral port after binding with port `0`.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner
            .as_ref()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotConnected))?
            .local_addr()
    }
}

impl Listener for WsListener {
    fn accept(&mut self) -> Result<Box<dyn Transport>> {
        let listener = match &self.inner {
            Some(l) => l,
            None => return ClosedSnafu.fail(),
        };
        let (stream, _peer) = listener.accept().map_err(crate::transport::io_to_closed)?;
        // Disable Nagle on accepted streams for the same latency
        // reasons as dial-out peers (TC round messages are small and
        // bursty — see TODO.roadmap/05 §Performance).
        stream.set_nodelay(true).ok();
        // Upgrade the raw TCP stream to a WebSocket by performing the
        // server-side handshake (RFC 6455 §4.2).
        let ws = tungstenite::accept(stream).map_err(crate::transport::handshake_to_closed)?;
        Ok(Box::new(WsTransport::from_server(ws)))
    }
}

impl Drop for WsListener {
    fn drop(&mut self) {
        // Dropping the inner listener closes the socket; take() is
        // for explicitness so a future `close` method can report
        // errors.
        self.inner.take();
    }
}
