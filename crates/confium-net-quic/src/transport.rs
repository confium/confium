//! Connected QUIC transport, shared framing, and the registry kind.
//!
//! [`QuicTransport`] owns one bidirectional QUIC stream on a Quinn
//! `Connection`. Each `send` is written as a 4-byte big-endian length
//! prefix followed by the payload; each `recv` reads exactly one framed
//! message. This mirrors the TCP transport so cross-transport message
//! semantics are identical: one `send` is observed as exactly one
//! `recv` payload, even though the underlying QUIC stream is a byte
//! stream.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;

use quinn::Connection;
use quinn::Endpoint;
use url::Url;

use confium_net::Listener;
use confium_net::Result;
use confium_net::Transport;
use confium_net::error::ClosedSnafu;
use confium_net::error::MalformedUrlSnafu;
use confium_net::registry::TransportKind;

use crate::runtime::Handle;
use crate::tls;

/// Maximum payload size for a single frame (8 MiB). Guards against a
/// malicious or buggy peer sending a gigantic length prefix that would
/// cause the receiver to allocate unbounded memory. Matches the TCP
/// transport's limit.
pub(crate) const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

/// Connected QUIC transport. Owns the async runtime, the Quinn
/// endpoint, the connection, and the bidirectional stream used for
/// framed messages.
pub struct QuicTransport {
    rt: Handle,
    // Order matters: fields drop in declaration order. The connection
    // must outlive the streams (they borrow its internal state), and
    // the endpoint must outlive the connection (it owns the UDP
    // socket the connection sends over).
    endpoint: Option<Endpoint>,
    conn: Option<Connection>,
    stream: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
}

impl QuicTransport {
    /// Wrap an already-accepted connection (server side). Used by
    /// [`crate::listener::QuicListener`] for inbound peers.
    ///
    /// Completes a 1-byte handshake so the client's `connect()` knows
    /// the server is ready before the client is allowed to send data
    /// or tear the connection down. Without this handshake a client
    /// that connects, sends, and closes quickly can race the server's
    /// `accept_bi` (see the note on connection establishment order in
    /// [`QuicTransport::connect`]).
    pub(crate) fn from_connection(rt: Handle, conn: Connection) -> std::io::Result<Self> {
        let (mut send, mut recv) = rt
            .block_on(conn.accept_bi())
            .map_err(|e| io_error("accept_bi (server)", e))?;
        // Read the client's SYN byte, then write the ACK byte. Both
        // are bare single bytes outside the length-prefix framing —
        // they exist only to coordinate stream readiness and are
        // consumed entirely before any framed data crosses the wire.
        rt.block_on(async {
            let mut syn = [0u8; 1];
            loop {
                match recv
                    .read(&mut syn)
                    .await
                    .map_err(|e| io_error("handshake syn read", e))?
                {
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "no SYN byte from client",
                        ));
                    }
                    Some(0) => continue,
                    Some(_) => break,
                }
            }
            send.write_all(b"\x01")
                .await
                .map_err(|e| io_error("handshake ack write", e))
        })?;
        Ok(Self {
            rt,
            endpoint: None,
            conn: Some(conn),
            stream: Some(send),
            recv: Some(recv),
        })
    }

    /// Connect a new endpoint to `host:port`, honoring the
    /// address-family hint `quic4` / `quic6` / `quic` encoded in
    /// `scheme`.
    ///
    /// After the QUIC handshake completes, the client opens a
    /// bidirectional stream and completes a 1-byte SYN/ACK exchange
    /// with the server. `connect()` does not return until the server
    /// has acknowledged, which closes the establishment-order race:
    /// the client cannot send data or drop the connection before the
    /// server has called `from_connection` and is ready to receive.
    pub(crate) fn connect(scheme: &str, host: &str, port: u16) -> std::io::Result<Self> {
        let rt = Handle::new()?;
        let addr = resolve_addr(scheme, host, port)?;

        let client_cfg = tls::client_config().map_err(|e| io_error_str("client TLS config", &e))?;

        // Bind a client-side endpoint on the matching address family.
        // Quinn requires a local socket even for clients; bind to the
        // wildcard of the same family as the destination so the kernel
        // picks a route.
        let bind_addr = match addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };

        // Everything from here runs inside `block_on` so quinn's
        // internal driver tasks (spawned via `tokio::spawn` when the
        // endpoint starts processing) are driven by this runtime.
        let (endpoint, conn) = rt.block_on(async {
            let endpoint =
                Endpoint::client(bind_addr).map_err(|e| io_error("bind client endpoint", e))?;
            let conn = endpoint
                .connect_with(client_cfg, addr, "localhost")
                .map_err(|e| io_error("start connect", e))?
                .await
                .map_err(|e| io_error("connect handshake", e))?;
            Ok::<(Endpoint, Connection), std::io::Error>((endpoint, conn))
        })?;

        // Open the bidirectional stream and complete the SYN/ACK
        // handshake (see `from_connection`). The SYN byte also forces
        // quinn to emit a STREAM frame immediately — without it,
        // `open_bi` is lazy and the server's `accept_bi` would not
        // resolve until the first real `send`, which is too late for
        // the establishment-order race described above.
        let (mut send, mut recv) = rt
            .block_on(conn.open_bi())
            .map_err(|e| io_error("open_bi (client)", e))?;
        rt.block_on(async {
            send.write_all(b"\x01")
                .await
                .map_err(|e| io_error("handshake syn write", e))?;
            let mut ack = [0u8; 1];
            loop {
                match recv
                    .read(&mut ack)
                    .await
                    .map_err(|e| io_error("handshake ack read", e))?
                {
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "no ACK byte from server",
                        ));
                    }
                    Some(0) => continue,
                    Some(_) => break,
                }
            }
            Ok::<(), std::io::Error>(())
        })?;

        Ok(Self {
            rt,
            endpoint: Some(endpoint),
            conn: Some(conn),
            stream: Some(send),
            recv: Some(recv),
        })
    }
}

impl Transport for QuicTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        let stream = match &mut self.stream {
            Some(s) => s,
            None => return ClosedSnafu.fail(),
        };
        self.rt
            .block_on(async {
                write_frame(stream, data).await?;
                Ok::<(), std::io::Error>(())
            })
            .map_err(quinn_io_to_closed)?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let recv = match &mut self.recv {
            Some(r) => r,
            None => return ClosedSnafu.fail(),
        };
        match self.rt.block_on(read_frame(recv, buf)) {
            Ok(Some(n)) => Ok(n),
            Ok(None) => ClosedSnafu.fail(),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => ClosedSnafu.fail(),
            Err(e) => Err(quinn_io_to_closed(e)),
        }
    }

    fn close(&mut self) -> Result<()> {
        // Gracefully close the send half (signals FIN to the peer so
        // its `recv` observes clean end-of-stream) and stop the recv
        // half. After `finish` we sleep briefly so quinn's endpoint
        // driver has a chance to flush the FIN and any pending stream
        // data to the wire before the transport drops and tears down
        // the connection. Without this, the implicit connection close
        // that happens on Drop could race ahead of the flush and the
        // peer would see a `Closed` instead of the buffered message.
        //
        // We deliberately do NOT call `reset` (discards in-flight
        // data) or `Endpoint::close` / `Connection::close` (sends
        // CONNECTION_CLOSE which aborts everything).
        self.flush_and_close_streams();
        Ok(())
    }
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        self.flush_and_close_streams();
        // Drop order (fields drop in declaration order): stream,
        // recv, conn, endpoint. The connection is dropped before the
        // endpoint, which lets quinn flush any pending stream data
        // before releasing the UDP socket.
        self.conn.take();
        self.endpoint.take();
    }
}

impl QuicTransport {
    /// Shared teardown: finish the send half, stop the recv half, and
    /// give the runtime a moment to flush before the caller drops the
    /// connection. See [`QuicTransport::close`] for why the sleep is
    /// necessary.
    fn flush_and_close_streams(&mut self) {
        if let Some(mut s) = self.stream.take() {
            self.rt.block_on(async {
                let _ = s.finish();
                // Brief sleep — loopback round-trips in well under
                // 10 ms in practice. We cannot use `SendStream::closed`
                // (quinn does not expose it) to wait for a precise
                // ack, so a conservative timer is the practical
                // alternative.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            });
        }
        if let Some(mut r) = self.recv.take() {
            self.rt.block_on(async {
                let _ = r.stop(0u32.into());
            });
        }
    }
}

// ---- registry kind ---------------------------------------------------

/// Registry kind for `quic`, `quic4`, `quic6`.
pub struct QuicTransportKind;

impl TransportKind for QuicTransportKind {
    fn schemes(&self) -> &'static [&'static str] {
        &["quic", "quic4", "quic6"]
    }

    fn connect(&self, url: &Url) -> Result<Box<dyn Transport>> {
        let scheme = url.scheme();
        let (host, port) = host_port(url, scheme)?;
        match QuicTransport::connect(scheme, host, port) {
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
        match crate::listener::QuicListener::bind(scheme, host, port) {
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

// ---- shared helpers --------------------------------------------------

/// Extract the `(host, port)` pair from a `quic*://` URL. The port is
/// mandatory.
pub(crate) fn host_port<'a>(url: &'a Url, scheme: &str) -> Result<(&'a str, u16)> {
    let host = url.host_str().unwrap_or("");
    if host.is_empty() {
        return MalformedUrlSnafu {
            scheme,
            url: url.to_string(),
            reason: "missing host (use quic://<host>:<port>)",
        }
        .fail();
    }
    let port = match url.port() {
        Some(p) => p,
        None => {
            return MalformedUrlSnafu {
                scheme,
                url: url.to_string(),
                reason: "missing port (use quic://<host>:<port>)",
            }
            .fail();
        }
    };
    Ok((host, port))
}

/// Map a scheme to its address-family constraint: `Some(true)` for
/// `quic6`, `Some(false)` for `quic4`, `None` for `quic` (any family).
pub(crate) fn address_family(scheme: &str) -> Option<bool> {
    match scheme {
        "quic4" => Some(false),
        "quic6" => Some(true),
        _ => None,
    }
}

/// Resolve `(scheme, host, port)` to a [`SocketAddr`], honoring the
/// `quic4` / `quic6` family hint. For bare `quic`, the host must be an
/// IP literal (no DNS — Confium transport URLs address concrete peers).
///
/// IPv6 hosts arrive bracketed from `url::Url` (e.g. `"[::1]"`); the
/// brackets are stripped before parsing.
pub(crate) fn resolve_addr(scheme: &str, host: &str, port: u16) -> std::io::Result<SocketAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match address_family(scheme) {
        Some(false) => {
            let ip: Ipv4Addr = host
                .parse()
                .map_err(|_| invalid_host(host, "not an IPv4 literal"))?;
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        Some(true) => {
            let ip: Ipv6Addr = host
                .parse()
                .map_err(|_| invalid_host(host, "not an IPv6 literal"))?;
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        None => {
            let ip: IpAddr = host
                .parse()
                .map_err(|_| invalid_host(host, "not an IP literal"))?;
            Ok(SocketAddr::new(ip, port))
        }
    }
}

fn invalid_host(host: &str, reason: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid host '{host}': {reason}"),
    )
}

// ---- async framing ---------------------------------------------------

/// Write one length-prefixed frame to the Quinn send stream.
async fn write_frame(w: &mut quinn::SendStream, data: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds 4 GiB length-prefix limit",
        )
    })?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    // Do not call `finish()` here: we keep the stream open for further
    // frames. The peer reads framed messages back-to-back.
    Ok(())
}

/// Read exactly one length-prefixed frame from the Quinn receive
/// stream into `buf`. Returns `Ok(None)` on clean EOF at a frame
/// boundary.
async fn read_frame(r: &mut quinn::RecvStream, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
    let mut prefix = [0u8; 4];
    if !fill_exact(r, &mut prefix).await? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(prefix);
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds maximum {MAX_FRAME_LEN}"),
        ));
    }
    let len = len as usize;
    let n = std::cmp::min(len, buf.len());
    read_exact(r, &mut buf[..n]).await?;
    // Drain and discard any bytes beyond the caller's buffer so the
    // stream is positioned at the start of the next frame.
    let mut remaining = len - n;
    let mut sink = [0u8; 4096];
    while remaining > 0 {
        let want = remaining.min(sink.len());
        match r.read(&mut sink[..want]).await? {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream closed mid-frame",
                ));
            }
            Some(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream closed mid-frame",
                ));
            }
            Some(got) => remaining -= got,
        }
    }
    Ok(Some(n))
}

async fn fill_exact(r: &mut quinn::RecvStream, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]).await? {
            None | Some(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream closed inside length prefix",
                ));
            }
            Some(n) => filled += n,
        }
    }
    Ok(true)
}

async fn read_exact(r: &mut quinn::RecvStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]).await? {
            None | Some(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream closed mid-frame",
                ));
            }
            Some(n) => filled += n,
        }
    }
    Ok(())
}

// ---- error mapping ---------------------------------------------------

fn io_error<E: std::fmt::Display>(ctx: &str, e: E) -> std::io::Error {
    std::io::Error::other(format!("{ctx}: {e}"))
}

fn io_error_str(ctx: &str, e: &str) -> std::io::Error {
    std::io::Error::other(format!("{ctx}: {e}"))
}

/// Map an [`std::io::Error`] from the async QUIC path to a
/// [`confium_net::Error`]. As with the TCP transport, the confium-net
/// error type does not carry an arbitrary I/O source, so QUIC failures
/// are reported as `Closed` — the transport is unusable after an I/O
/// failure.
pub(crate) fn quinn_io_to_closed(_: std::io::Error) -> confium_net::Error {
    ClosedSnafu.build()
}
