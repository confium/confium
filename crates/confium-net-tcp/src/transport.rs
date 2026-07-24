//! Connected TCP transport and the shared length-prefix framing layer.
//!
//! [`TcpTransport`] wraps a [`std::net::TcpStream`] and implements
//! [`confium_net::Transport`]. Each `send` is written to the socket as
//! a 4-byte big-endian length prefix followed by the payload bytes;
//! each `recv` reads exactly one framed message (repeating partial-read
//! calls until the full payload is in hand) so the
//! "one `send` == one `recv`" contract holds over the byte stream.
//!
//! The framing helpers ([`write_frame`], [`read_frame`]) live here and
//! are reused by [`crate::listener::TcpListener`] for accepted streams.

use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;

use url::Url;

use confium_net::Listener;
use confium_net::Result;
use confium_net::Transport;
use confium_net::error::ClosedSnafu;
use confium_net::error::MalformedUrlSnafu;
use confium_net::registry::TransportKind;

/// Maximum payload size for a single frame (8 MiB). Guards against a
/// malicious or buggy peer sending a gigantic length prefix that would
/// cause the receiver to allocate unbounded memory.
pub(crate) const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

// ---- framing ---------------------------------------------------------

/// Write one length-prefixed frame: 4-byte big-endian length, then the
/// payload. Partial writes are repeated until the whole frame is on the
/// wire.
pub(crate) fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds 4 GiB length-prefix limit",
        )
    })?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

/// Read exactly one length-prefixed frame into `buf`, returning:
///
/// - `Ok(Some(n))` — a frame of length `n` was read into `buf`. If the
///   buffer was smaller than the frame, `n == buf.len()` and the
///   remainder of the frame is drained and discarded, matching the
///   built-in `inproc` transport's "fill what you can, drop the rest"
///   semantics for undersized buffers.
/// - `Ok(None)` — the peer closed the stream cleanly at a frame
///   boundary (zero bytes of the next length prefix arrived before
///   EOF). The caller should translate this to `Error::Closed`.
///
/// Any I/O failure, including EOF inside a length prefix or mid-frame,
/// is returned as `Err`.
pub(crate) fn read_frame<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
    let mut prefix = [0u8; 4];
    if !fill_exact(r, &mut prefix)? {
        // Clean EOF at a frame boundary.
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
    // Read the bytes the caller will receive.
    read_exact(r, &mut buf[..n])?;
    // Drain and discard any bytes beyond the caller's buffer so the
    // socket is positioned at the start of the next frame.
    let mut remaining = len - n;
    let mut sink = [0u8; 4096];
    while remaining > 0 {
        let want = remaining.min(sink.len());
        match r.read(&mut sink[..want])? {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream closed mid-frame",
                ));
            }
            got => remaining -= got,
        }
    }
    Ok(Some(n))
}

/// Read exactly `buf.len()` bytes. Returns `Ok(false)` if the stream
/// reached EOF before **any** byte was read (a clean boundary); returns
/// `Ok(true)` once `buf` is full. A short read partway through `buf`
/// is `UnexpectedEof` — the peer closed inside a frame.
fn fill_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream closed inside length prefix",
                ));
            }
            n => filled += n,
        }
    }
    Ok(true)
}

/// Read exactly `buf.len()` bytes, erroring on any short read. Used
/// after the length prefix is fully read, so any EOF here is mid-frame.
fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream closed mid-frame",
                ));
            }
            n => filled += n,
        }
    }
    Ok(())
}

// ---- connected transport --------------------------------------------

/// Connected TCP transport. Owns the underlying [`TcpStream`]; `close`
/// shuts both directions of the stream down so the peer observes a
/// clean end-of-stream.
pub struct TcpTransport {
    stream: Option<TcpStream>,
}

impl TcpTransport {
    /// Wrap an already-connected stream (used by
    /// [`crate::listener::TcpListener`] for accepted peers).
    pub(crate) fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    /// Connect a new stream to `host:port`, honoring the
    /// address-family hint `tcp4` / `tcp6` / `tcp` encoded in `scheme`.
    pub(crate) fn connect(scheme: &str, host: &str, port: u16) -> std::io::Result<Self> {
        let stream = match address_family(scheme) {
            Some(false) => {
                // tcp4: force IPv4.
                let ip: IpAddr = host
                    .parse()
                    .map_err(|_| invalid_host(host, "not an IPv4 literal"))?;
                if !ip.is_ipv4() {
                    return Err(invalid_host(host, "not an IPv4 literal"));
                }
                TcpStream::connect(SocketAddr::new(ip, port))?
            }
            Some(true) => {
                // tcp6: force IPv6.
                let ip: IpAddr = host
                    .parse()
                    .map_err(|_| invalid_host(host, "not an IPv6 literal"))?;
                if !ip.is_ipv6() {
                    return Err(invalid_host(host, "not an IPv6 literal"));
                }
                TcpStream::connect(SocketAddr::new(ip, port))?
            }
            None => {
                // tcp: any family. `host:port` is resolved by the
                // standard library via `ToSocketAddrs` (covers literal
                // IPs and DNS names).
                TcpStream::connect((host, port))?
            }
        };
        // Disable Nagle: threshold-cryptography traffic is bursty, small
        // round messages where the latency cost of coalescing outweighs
        // the bandwidth saving. (TODO.roadmap/05: "latency matters more
        // than throughput" for typical TC schemes.)
        stream.set_nodelay(true).ok();
        Ok(Self::from_stream(stream))
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        let stream = match &mut self.stream {
            Some(s) => s,
            None => return ClosedSnafu.fail(),
        };
        write_frame(stream, data).map_err(io_to_closed)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let stream = match &mut self.stream {
            Some(s) => s,
            None => return ClosedSnafu.fail(),
        };
        match read_frame(stream, buf) {
            Ok(Some(n)) => Ok(n),
            // Clean EOF at a frame boundary: peer closed cleanly.
            Ok(None) => ClosedSnafu.fail(),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => ClosedSnafu.fail(),
            Err(e) => Err(io_to_closed(e)),
        }
    }

    fn close(&mut self) -> Result<()> {
        if let Some(stream) = self.stream.take() {
            // Best-effort: the peer may have already closed their end.
            stream.shutdown(Shutdown::Both).ok();
        }
        Ok(())
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            stream.shutdown(Shutdown::Both).ok();
        }
    }
}

// ---- registry kind ---------------------------------------------------

/// Registry kind for `tcp`, `tcp4`, `tcp6`.
pub struct TcpTransportKind;

impl TransportKind for TcpTransportKind {
    fn schemes(&self) -> &'static [&'static str] {
        &["tcp", "tcp4", "tcp6"]
    }

    fn connect(&self, url: &Url) -> Result<Box<dyn Transport>> {
        let scheme = url.scheme();
        let (host, port) = host_port(url, scheme)?;
        match TcpTransport::connect(scheme, host, port) {
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
        match crate::listener::TcpListener::bind(scheme, host, port) {
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

/// Extract the `(host, port)` pair from a `tcp*://` URL. The port is
/// mandatory for TCP (unlike `inproc` which carries a channel name).
pub(crate) fn host_port<'a>(url: &'a Url, scheme: &str) -> Result<(&'a str, u16)> {
    let host = url.host_str().unwrap_or("");
    if host.is_empty() {
        return MalformedUrlSnafu {
            scheme,
            url: url.to_string(),
            reason: "missing host (use tcp://<host>:<port>)",
        }
        .fail();
    }
    let port = match url.port() {
        Some(p) => p,
        None => {
            return MalformedUrlSnafu {
                scheme,
                url: url.to_string(),
                reason: "missing port (use tcp://<host>:<port>)",
            }
            .fail();
        }
    };
    Ok((host, port))
}

/// Map a scheme to its address-family constraint: `Some(true)` for
/// `tcp6`, `Some(false)` for `tcp4`, `None` for `tcp` (any family).
pub(crate) fn address_family(scheme: &str) -> Option<bool> {
    match scheme {
        "tcp4" => Some(false),
        "tcp6" => Some(true),
        _ => None,
    }
}

fn invalid_host(host: &str, reason: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid host '{host}': {reason}"),
    )
}

/// Map an [`std::io::Error`] to a [`confium_net::Error`]. The
/// confium-net error type does not today carry an arbitrary I/O source,
/// so connection / read / write failures are reported as `Closed` —
/// the transport is unusable after an I/O failure, matching how the
/// inproc transport reports a broken channel.
pub(crate) fn io_to_closed(_: std::io::Error) -> confium_net::Error {
    ClosedSnafu.build()
}
