//! Listening endpoint for `tcp://`, `tcp4://`, `tcp6://` URLs.
//!
//! [`TcpListener`] wraps [`std::net::TcpListener`] and implements
//! [`confium_net::Listener`]. Each [`accept`](confium_net::Listener::accept)
//! yields a [`crate::TcpTransport`] wrapping the accepted
//! [`std::net::TcpStream`], so accepted peers speak the same
//! length-prefixed framing as dial-out peers.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::TcpListener as StdTcpListener;

use confium_net::Listener;
use confium_net::Result;
use confium_net::Transport;
use confium_net::error::ClosedSnafu;

use crate::TcpTransport;
use crate::transport::address_family;

/// Listening endpoint for inbound TCP connections.
///
/// Holding this alive keeps the bound socket open; dropping it closes
/// the socket (the OS releases the port).
pub struct TcpListener {
    inner: Option<StdTcpListener>,
}

impl TcpListener {
    /// Bind a new listener at `host:port`, honoring the address-family
    /// hint `tcp4` / `tcp6` / `tcp` encoded in `scheme`. Passing port
    /// `0` requests an ephemeral port from the OS; the caller can read
    /// the assigned port back via [`local_addr`](Self::local_addr).
    pub fn bind(scheme: &str, host: &str, port: u16) -> std::io::Result<Self> {
        let listener = match address_family(scheme) {
            Some(false) => {
                // tcp4: bind IPv4 only. `host` may be a literal IPv4 or
                // the wildcard `0.0.0.0`.
                let ip: Ipv4Addr = parse_ipv4(host)?;
                StdTcpListener::bind(SocketAddr::new(IpAddr::V4(ip), port))?
            }
            Some(true) => {
                // tcp6: bind IPv6 only.
                let ip: Ipv6Addr = parse_ipv6(host)?;
                StdTcpListener::bind(SocketAddr::new(IpAddr::V6(ip), port))?
            }
            None => {
                // tcp: let the standard library resolve `host:port`
                // (literal IP, `0.0.0.0`, `[::]`, or DNS name). Bind to
                // the first working address.
                StdTcpListener::bind((host, port))?
            }
        };
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

impl Listener for TcpListener {
    fn accept(&mut self) -> Result<Box<dyn Transport>> {
        let listener = match &self.inner {
            Some(l) => l,
            None => return ClosedSnafu.fail(),
        };
        let (stream, _peer) = listener.accept().map_err(crate::transport::io_to_closed)?;
        // Disable Nagle on accepted streams for the same latency
        // reasons as dial-out peers (see [`TcpTransport::connect`]).
        stream.set_nodelay(true).ok();
        Ok(Box::new(TcpTransport::from_stream(stream)))
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        // Dropping the inner listener closes the socket; take() is for
        // explicitness so a future `close` method can report errors.
        self.inner.take();
    }
}

fn parse_ipv4(host: &str) -> std::io::Result<Ipv4Addr> {
    host.parse::<Ipv4Addr>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid IPv4 bind address '{host}'"),
        )
    })
}

fn parse_ipv6(host: &str) -> std::io::Result<Ipv6Addr> {
    host.parse::<Ipv6Addr>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid IPv6 bind address '{host}'"),
        )
    })
}
