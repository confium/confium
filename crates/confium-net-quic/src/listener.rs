//! Listening endpoint for `quic://`, `quic4://`, `quic6://` URLs.
//!
//! [`QuicListener`] wraps a Quinn [`Endpoint`] configured as a server
//! and implements [`confium_net::Listener`]. Each
//! [`accept`](confium_net::Listener::accept) drives the Quinn
//! `accept` future on the listener's owned runtime, then wraps the
//! accepted [`Connection`](quinn::Connection) in a
//! [`crate::QuicTransport`], so accepted peers speak the same
//! length-prefixed framing as dial-out peers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::Endpoint;
use quinn::IdleTimeout;
use quinn::TransportConfig;

use confium_net::Listener;
use confium_net::Result;
use confium_net::Transport;
use confium_net::error::ClosedSnafu;

use crate::QuicTransport;
use crate::runtime::Handle;
use crate::tls;
use crate::transport::quinn_io_to_closed;
use crate::transport::resolve_addr;

/// Listening endpoint for inbound QUIC connections.
///
/// Holding this alive keeps the bound UDP socket open; dropping it
/// closes the endpoint (the OS releases the port).
pub struct QuicListener {
    rt: Handle,
    endpoint: Option<Endpoint>,
}

impl QuicListener {
    /// Bind a new listener at `host:port`, honoring the address-family
    /// hint `quic4` / `quic6` / `quic` encoded in `scheme`. Passing
    /// port `0` requests an ephemeral port from the OS; the caller can
    /// read the assigned port back via [`local_addr`](Self::local_addr).
    pub fn bind(scheme: &str, host: &str, port: u16) -> std::io::Result<Self> {
        let addr = resolve_addr(scheme, host, port)?;
        let rt = Handle::new()?;

        let mut server_cfg =
            tls::server_config().map_err(|e| io_error_str("server TLS config", &e))?;

        // Generous idle timeout so long-lived TC sessions (minutes
        // between rounds) are not prematurely torn down.
        let mut tc = TransportConfig::default();
        tc.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(300)).expect("300s is a valid idle timeout"),
        ));
        server_cfg.transport_config(Arc::new(tc));

        let endpoint = rt
            .block_on(async { Endpoint::server(server_cfg, addr) })
            .map_err(|e| io_error("bind server endpoint", e))?;

        Ok(Self {
            rt,
            endpoint: Some(endpoint),
        })
    }

    /// The locally-bound socket address. Useful for reading back the
    /// OS-assigned ephemeral port after binding with port `0`.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotConnected))?;
        endpoint.local_addr().map_err(|e| io_error("local_addr", e))
    }
}

impl Listener for QuicListener {
    fn accept(&mut self) -> Result<Box<dyn Transport>> {
        let endpoint = match &self.endpoint {
            Some(e) => e,
            None => return ClosedSnafu.fail(),
        };
        let rt = self.rt.clone();
        let incoming = match rt.block_on(async { endpoint.accept().await }) {
            Some(i) => i,
            None => return ClosedSnafu.fail(),
        };
        let conn: quinn::Connection = rt
            .block_on(async { incoming.await })
            .map_err(|e| io_error("accept handshake", e))
            .map_err(quinn_io_to_closed)?;
        let transport = QuicTransport::from_connection(rt, conn).map_err(quinn_io_to_closed)?;
        Ok(Box::new(transport))
    }
}

impl Drop for QuicListener {
    fn drop(&mut self) {
        if let Some(ep) = self.endpoint.take() {
            self.rt.block_on(async {
                ep.close(0u32.into(), &[]);
            });
        }
    }
}

fn io_error<E: std::fmt::Display>(ctx: &str, e: E) -> std::io::Error {
    std::io::Error::other(format!("{ctx}: {e}"))
}

fn io_error_str(ctx: &str, e: &str) -> std::io::Error {
    std::io::Error::other(format!("{ctx}: {e}"))
}
