//! WebSocket transport for Confium.
//!
//! `ws://host:port[/path]` and `wss://host:port[/path]` URLs address a
//! peer reachable over a WebSocket connection (RFC 6455). A
//! [`WsListener`] bound via `ws://0.0.0.0:port` accepts inbound
//! connections and yields [`WsTransport`] handles on
//! [`confium_net::Listener::accept`].
//!
//! WebSocket is a natural fit for browser- or cloud-hosted threshold
//! parties: it tunnels cleanly through HTTP infrastructure (proxies,
//! load balancers, TLS terminators) while still carrying arbitrary
//! binary protocol messages. Each [`confium_net::Transport::send`] is
//! delivered as one WebSocket binary frame so the
//! "one `send` == one `recv`" contract holds — message framing is
//! native to the WebSocket protocol, no length-prefix layer is needed
//! (unlike the raw-TCP transport in `confium-net-tcp`).
//!
//! `wss://` enables TLS via rustls using the platform's native CA
//! store (the `rustls-tls-native-roots` feature of `tungstenite`).
//! Server-side `wss://` (TLS termination at the listener) is not
//! implemented in this crate; deploy a TLS-terminating reverse proxy
//! (nginx, Caddy, an HTTP load balancer) in front of a plain
//! `ws://` listener instead.
//!
//! See `TODO.roadmap/05-networking-primitives.md` for the design and
//! the `confium_net` crate for the trait definitions.
//!
//! # Schemes
//!
//! - `ws` — plain WebSocket over TCP.
//! - `wss` — TLS-protected WebSocket (client side only; see note
//!   above).

pub mod listener;
pub mod transport;

pub use listener::WsListener;
pub use transport::WsTransport;
pub use transport::WsTransportKind;

use confium_net::register_transport;

// One kind owns both schemes, mirroring how the built-in `InprocKind`
// owns the `inproc` scheme. `register_transport!` submits it to the
// link-time inventory so `confium_net::connect` /
// `confium_net::listen` can dispatch to it by scheme.
register_transport!(WsTransportKind);
