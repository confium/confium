#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

//! Confium Network: transport abstraction for multi-party protocols.
//!
//! Threshold-cryptography sessions need reliable, ordered byte streams
//! between parties. Confium supplies the transport so plugin authors
//! don't roll their own socket code. Plugins request a transport by
//! URL (`"inproc://session-42"`, `"tcp://1.2.3.4:443"`, ...); Confium
//! dispatches to the registered [`TransportKind`] that owns the
//! scheme.
//!
//! # Built-in transports
//!
//! This crate ships two built-in transports:
//!
//! - [`transports::inproc`] — in-process channels for tests and
//!   single-process TC simulation.
//! - [`transports::mock`] — deterministic mock transport with
//!   drop/tamper fault injection for Byzantine-peer simulation.
//!
//! Production transports (`tcp`, `tcp+tls`, `quic`, `ws`, `wss`) live
//! in separate crates (`confium-net-tcp`, etc.) and register via the
//! same [`register_transport!`] macro.
//!
//! # Example
//!
//! ```
//! use confium_net as net;
//!
//! // Listener must be set up before connect consumes it.
//! let mut listener = net::listen("inproc://demo").unwrap();
//! let mut client = net::connect("inproc://demo").unwrap();
//! let mut server = listener.accept().unwrap();
//!
//! client.send(b"round-1").unwrap();
//! let mut buf = [0u8; 16];
//! let n = server.recv(&mut buf).unwrap();
//! assert_eq!(&buf[..n], b"round-1");
//! ```
//!
//! See `TODO.roadmap/05-networking-primitives.md` for the design.

pub mod error;
pub mod registry;
pub mod transports;
pub mod url;

use ::url::Url;
use snafu::OptionExt;

pub use error::Error;
pub use error::Result;
pub use registry::TransportKind;
// `register_transport!` is exported via `#[macro_export]`, so it is
// already at the crate root and part of the public API.
pub use transports::inproc;
pub use transports::mock;
pub use url::TransportUrl;

use error::UnknownSchemeSnafu;

/// A connected, reliable, ordered, bidirectional byte transport.
///
/// Implementations deliver complete protocol messages: one `send` is
/// observed as exactly one `recv` payload. Callers provide a buffer to
/// `recv`; if the buffer is smaller than the pending message, the
/// transport fills what it can. Specific transports document how they
/// handle undersized buffers (the built-in `inproc`/`mock` transports
/// deliver a prefix and drop the remainder).
pub trait Transport: Send {
    /// Enqueue `data` for delivery to the peer.
    fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Receive the next pending message into `buf`, returning the
    /// number of bytes written.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Tear down the transport. After this, `send` and `recv` return
    /// [`Error::Closed`].
    fn close(&mut self) -> Result<()>;
}

/// A listening endpoint that produces accepted [`Transport`]s.
pub trait Listener: Send {
    /// Block until a peer connects, then return the new transport.
    fn accept(&mut self) -> Result<Box<dyn Transport>>;
}

/// Connect to the peer identified by `url_str`.
///
/// The URL scheme selects the transport kind via the link-time
/// registry. The built-in `inproc` and `mock` schemes are always
/// available; additional schemes require their transport crate to be
/// linked into the final binary.
pub fn connect(url_str: &str) -> Result<Box<dyn Transport>> {
    let parsed = TransportUrl::parse(url_str)?;
    let scheme = parsed.scheme();
    let kind = registry::find(scheme).with_context(|| UnknownSchemeSnafu {
        scheme: scheme.to_string(),
    })?;
    let url: &Url = parsed.as_url();
    kind.connect(url)
}

/// Begin listening for inbound connections at the address in
/// `url_str`.
pub fn listen(url_str: &str) -> Result<Box<dyn Listener>> {
    let parsed = TransportUrl::parse(url_str)?;
    let scheme = parsed.scheme();
    let kind = registry::find(scheme).with_context(|| UnknownSchemeSnafu {
        scheme: scheme.to_string(),
    })?;
    let url: &Url = parsed.as_url();
    kind.listen(url)
}
