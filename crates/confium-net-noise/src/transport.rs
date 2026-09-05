//! Noise transport: handshake + session over a framed TCP stream.

use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use snafu::IntoError;
use snafu::ResultExt;
use snow::Builder;
use snow::HandshakeState;
use snow::TransportState;
use url::Url;

use confium_net::Listener;
use confium_net::Result;
use confium_net::Transport;
use confium_net::error::ClosedSnafu;
use confium_net::error::IoSnafu;
use confium_net::error::MalformedUrlSnafu;

use crate::keys::NoiseIdentity;
use crate::keys::fingerprint_of;
use crate::keys::hex;
use crate::keys::noise_params;

/// Maximum plaintext payload per frame (8 MiB), matching the TCP
/// transport's guard against hostile length prefixes. Ciphertext
/// frames carry at most this plus the Noise tag (16 bytes).
const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

/// Handshake frames use a smaller cap: snow handshake messages are
/// always far below this.
const MAX_HANDSHAKE_LEN: u32 = 65535;

/// snow caps transport-mode messages at 65535 bytes, so application
/// payloads larger than this are fragmented. Each encrypted chunk
/// carries a one-byte prefix — 0x00 = more chunks follow, 0x01 =
/// final — and the receiver reassembles before returning, preserving
/// the one-send-one-recv contract.
const MAX_CHUNK: usize = 60_000;

/// Parsed `noise://` URL parameters.
pub(crate) struct NoiseParams {
    pub addr: SocketAddr,
    /// Provisioned local static key (`key=<hex>`); ephemeral if absent.
    pub local_key: Option<NoiseIdentity>,
    /// Pinned remote fingerprint (`pinned=<hex>`).
    pub pinned: Option<[u8; 32]>,
}

pub(crate) fn parse_url(url: &Url) -> Result<NoiseParams> {
    let host = url.host_str().ok_or_else(|| {
        MalformedUrlSnafu {
            scheme: "noise",
            url: url.as_str(),
            reason: "noise URL requires a host",
        }
        .build()
    })?;
    let port = url.port().ok_or_else(|| {
        MalformedUrlSnafu {
            scheme: "noise",
            url: url.as_str(),
            reason: "noise URL requires an explicit port",
        }
        .build()
    })?;
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|_| {
            MalformedUrlSnafu {
                scheme: "noise",
                url: url.as_str(),
                reason: "could not resolve host and port",
            }
            .build()
        })?
        .next()
        .ok_or_else(|| {
            MalformedUrlSnafu {
                scheme: "noise",
                url: url.as_str(),
                reason: "no address resolved for host and port",
            }
            .build()
        })?;

    let mut local_key = None;
    let mut pinned = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "key" => {
                local_key = Some(NoiseIdentity::from_hex(&v).map_err(|_| {
                    MalformedUrlSnafu {
                        scheme: "noise",
                        url: url.as_str(),
                        reason: "key= must be 32 bytes of hex (private key)",
                    }
                    .build()
                })?);
            }
            "pinned" => {
                pinned = Some(
                    crate::keys::unhex(&v)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .ok_or_else(|| {
                            MalformedUrlSnafu {
                                scheme: "noise",
                                url: url.as_str(),
                                reason: "pinned= must be 32 bytes of hex (fingerprint)",
                            }
                            .build()
                        })?,
                );
            }
            _ => {}
        }
    }
    Ok(NoiseParams {
        addr,
        local_key,
        pinned,
    })
}

// ---- framing ---------------------------------------------------------

fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}

fn read_frame<R: Read>(r: &mut R, max: u32) -> std::io::Result<Option<Vec<u8>>> {
    let mut prefix = [0u8; 4];
    if !fill(r, &mut prefix)? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(prefix);
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds maximum {max}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    if !fill(r, &mut buf)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "EOF inside frame",
        ));
    }
    Ok(Some(buf))
}

fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Ok(false),
            Ok(n) => off += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

// ---- handshake -------------------------------------------------------

fn io_err(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

fn eof() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "peer closed during noise handshake",
    )
}

/// Run the Noise_XX handshake over a connected byte stream. Returns
/// the established session state and the remote static public key.
fn handshake<S: Read + Write>(
    stream: &mut S,
    identity: &NoiseIdentity,
    initiator: bool,
    pinned: Option<[u8; 32]>,
) -> std::io::Result<(TransportState, [u8; 32])> {
    let builder = Builder::new(noise_params())
        .local_private_key(&identity.private)
        .map_err(|e| io_err(format!("noise local key rejected: {e}")))?;
    let mut state: HandshakeState = if initiator {
        builder
            .build_initiator()
            .map_err(|e| io_err(format!("noise initiator build: {e}")))?
    } else {
        builder
            .build_responder()
            .map_err(|e| io_err(format!("noise responder build: {e}")))?
    };

    let mut buf = vec![0u8; MAX_HANDSHAKE_LEN as usize];
    while !state.is_handshake_finished() {
        if state.is_my_turn() {
            let n = state
                .write_message(&[], &mut buf)
                .map_err(|e| io_err(format!("noise handshake write: {e}")))?;
            write_frame(stream, &buf[..n])?;
        } else {
            let frame = read_frame(stream, MAX_HANDSHAKE_LEN)?.ok_or_else(eof)?;
            state
                .read_message(&frame, &mut buf)
                .map_err(|e| io_err(format!("noise handshake read: {e}")))?;
        }
    }

    let remote: [u8; 32] = state
        .get_remote_static()
        .ok_or_else(|| io_err("noise handshake finished without a remote static key".into()))?
        .try_into()
        .expect("noise static keys are 32 bytes");

    if let Some(expected) = pinned {
        let got = fingerprint_of(&remote);
        if got != expected {
            return Err(io_err(format!(
                "pinned fingerprint mismatch: expected {}, got {}",
                hex(&expected),
                hex(&got)
            )));
        }
    }

    state
        .into_transport_mode()
        .map(|t| (t, remote))
        .map_err(|e| io_err(format!("noise transport mode: {e}")))
}

// ---- transport -------------------------------------------------------

/// An established Noise session over TCP, framed per the
/// [`confium_net::Transport`] contract: one `send` observed as one
/// `recv` payload.
pub struct NoiseTransport {
    state: TransportState,
    stream: std::net::TcpStream,
    remote: [u8; 32],
}

impl NoiseTransport {
    /// SHA-256 fingerprint of the authenticated remote static key.
    pub fn remote_fingerprint(&self) -> [u8; 32] {
        fingerprint_of(&self.remote)
    }

    pub(crate) fn connect(params: &NoiseParams) -> Result<Self> {
        let identity = params
            .local_key
            .clone()
            .unwrap_or_else(NoiseIdentity::generate);
        let mut stream = std::net::TcpStream::connect(params.addr).context(IoSnafu)?;
        // A non-noise peer accepts the TCP connection and then never
        // speaks the handshake; without a deadline the client would
        // block on the first read forever. 10s bounds a stalled or
        // mismatched peer; established sessions are not affected.
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .context(IoSnafu)?;
        let (state, remote) =
            handshake(&mut stream, &identity, true, params.pinned).context(IoSnafu)?;
        stream.set_read_timeout(None).context(IoSnafu)?;
        Ok(Self {
            state,
            stream,
            remote,
        })
    }

    pub(crate) fn accept(stream: std::net::TcpStream, params: &NoiseParams) -> Result<Self> {
        let identity = params
            .local_key
            .clone()
            .unwrap_or_else(NoiseIdentity::generate);
        let mut stream = stream;
        let (state, remote) =
            handshake(&mut stream, &identity, false, params.pinned).context(IoSnafu)?;
        Ok(Self {
            state,
            stream,
            remote,
        })
    }
}

impl NoiseTransport {
    fn send_chunk(&mut self, data: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; data.len() + 128];
        let n = self
            .state
            .write_message(data, &mut buf)
            .map_err(|e| io_err(format!("noise write: {e}")))
            .context(IoSnafu)?;
        write_frame(&mut self.stream, &buf[..n]).context(IoSnafu)
    }

    fn recv_chunk(&mut self) -> Result<Vec<u8>> {
        let frame = read_frame(&mut self.stream, MAX_FRAME_LEN + 256)
            .context(IoSnafu)?
            .ok_or(ClosedSnafu.build())?;
        let mut plain = vec![0u8; frame.len()];
        let n = self
            .state
            .read_message(&frame, &mut plain)
            .map_err(|e| io_err(format!("noise decrypt failed: {e}")))
            .context(IoSnafu)?;
        plain.truncate(n);
        Ok(plain)
    }
}

impl Transport for NoiseTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_FRAME_LEN as usize {
            return Err(IoSnafu.into_error(io_err("payload exceeds frame maximum".into())));
        }
        if data.is_empty() {
            return self.send_chunk(&[0x01]);
        }
        let mut chunks = data.chunks(MAX_CHUNK).peekable();
        while let Some(chunk) = chunks.next() {
            let final_chunk = chunks.peek().is_none();
            let mut framed = Vec::with_capacity(chunk.len() + 1);
            framed.push(if final_chunk { 0x01 } else { 0x00 });
            framed.extend_from_slice(chunk);
            self.send_chunk(&framed)?;
        }
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut message = Vec::new();
        loop {
            let chunk = self.recv_chunk()?;
            if chunk.is_empty() {
                return Err(ClosedSnafu.build());
            }
            let (flag, body) = chunk.split_first().expect("chunk has flag byte");
            message.extend_from_slice(body);
            if *flag == 0x01 {
                break;
            }
        }
        let n = message.len().min(buf.len());
        buf[..n].copy_from_slice(&message[..n]);
        Ok(n)
    }

    fn close(&mut self) -> Result<()> {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

/// Accepts inbound Noise sessions on a TCP socket.
pub struct NoiseListener {
    inner: std::net::TcpListener,
    params: NoiseParams,
}

impl NoiseListener {
    pub(crate) fn new(params: NoiseParams) -> Result<Self> {
        let inner = std::net::TcpListener::bind(params.addr).context(IoSnafu)?;
        Ok(Self { inner, params })
    }

    /// The bound local address (useful when binding port 0 in tests).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl Listener for NoiseListener {
    fn accept(&mut self) -> Result<Box<dyn Transport>> {
        let (stream, _) = self.inner.accept().context(IoSnafu)?;
        Ok(Box::new(NoiseTransport::accept(stream, &self.params)?))
    }
}
