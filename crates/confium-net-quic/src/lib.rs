//! QUIC transport for Confium.
//!
//! `quic://host:port` URLs address a peer reachable over QUIC. A
//! [`QuicListener`] bound via `quic://0.0.0.0:port` accepts inbound
//! connections and yields [`QuicTransport`] handles on
//! [`confium_net::Listener::accept`].
//!
//! QUIC streams are reliable, ordered, and per-stream — but Confium's
//! [`confium_net::Transport`] contract is "one `send` == one `recv`
//! payload." Each transport handle opens a single bidirectional QUIC
//! stream and frames every message with a 4-byte big-endian length
//! prefix, mirroring the TCP transport so cross-transport semantics
//! are identical. (Future work could use one stream per message for
//! head-of-line-blocking freedom; the framing stays the same.)
//!
//! ## TLS / authentication
//!
//! QUIC mandates TLS 1.3. Confium's TC protocol signs each round
//! message at the application layer (see `TODO.roadmap/05-networking-
//! primitives.md`), so the transport itself uses an in-memory
//! self-signed certificate that the client accepts unconditionally
//! (`ServerConfig` peer verification disabled). This is the third
//! authentication option listed in the roadmap: "application-layer
//! signatures — TC session itself signs each round message; transport
//! is unauthenticated but the protocol is safe."
//!
//! ## Runtime
//!
//! Quinn is async. The [`confium_net::Transport`] / [`confium_net::Listener`]
//! traits are blocking. Each transport/listener handle drives its async
//! work via the shared runtime's `block_on`, presenting a synchronous
//! facade to callers.
//!
//! # Schemes
//!
//! - `quic` — accept either IPv4 or IPv6 addresses.
//! - `quic4` — restrict to IPv4.
//! - `quic6` — restrict to IPv6.

pub mod listener;
pub mod runtime;
pub mod tls;
pub mod transport;

pub use listener::QuicListener;
pub use transport::QuicTransport;
pub use transport::QuicTransportKind;

use confium_net::register_transport;

// One kind owns all three schemes. `register_transport!` submits it to
// the link-time inventory so `confium_net::connect` /
// `confium_net::listen` can dispatch to it by scheme.
register_transport!(QuicTransportKind);
