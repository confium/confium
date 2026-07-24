//! TCP transport for Confium.
//!
//! `tcp://host:port` URLs address a peer reachable over a plain TCP
//! socket. A [`TcpListener`] bound via `tcp://0.0.0.0:port` (or any
//! loopback / interface address) accepts inbound connections and yields
//! [`TcpTransport`] handles on [`confium_net::Listener::accept`].
//!
//! The transport wraps [`std::net::TcpStream`] /
//! [`std::net::TcpListener`] and frames each `send`/`recv` pair as one
//! length-prefixed message so the [`confium_net::Transport`] contract —
//! one `send` observed as one `recv` payload — holds over a byte-stream
//! socket. (Raw TCP does not preserve message boundaries; a 4-byte
//! big-endian length prefix does.)
//!
//! See `TODO.roadmap/05-networking-primitives.md` for the design and
//! the `confium_net` crate for the trait definitions.
//!
//! # Schemes
//!
//! - `tcp` — accept either IPv4 or IPv6 addresses.
//! - `tcp4` — restrict to IPv4 literals.
//! - `tcp6` — restrict to IPv6 literals.

pub mod listener;
pub mod transport;

pub use listener::TcpListener;
pub use transport::TcpTransport;
pub use transport::TcpTransportKind;

use confium_net::register_transport;

// One kind owns all three schemes, mirroring how the built-in
// `InprocKind` owns the `inproc` scheme. `register_transport!` submits
// it to the link-time inventory so `confium_net::connect` /
// `confium_net::listen` can dispatch to it by scheme.
register_transport!(TcpTransportKind);
