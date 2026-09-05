//! Noise_XX encrypted transport for Confium coordinator sessions.
//!
//! `noise://host:port` URLs address a peer reachable over TCP with a
//! Noise_XX (`Noise_XX_25519_ChaChaPoly_BLAKE2s`) handshake protecting
//! the session. Both sides exchange static keys during the handshake;
//! after it completes every frame is encrypted and authenticated by
//! the Noise state machine.
//!
//! URL parameters:
//!
//! - `key=<hex>` — the local static private key (32 bytes, hex). When
//!   absent an ephemeral key is generated, giving transport encryption
//!   with trust-on-first-use identity.
//! - `pinned=<hex>` — SHA-256 fingerprint of the expected remote
//!   static key (32 bytes, hex). When present the handshake aborts
//!   unless the peer's static key hashes to exactly this value.
//!
//! Message framing matches the TCP transport: one 4-byte big-endian
//! length-prefixed frame per `send`, so the
//! "one `send` observed as one `recv` payload" contract holds.
//!
//! # Schemes
//!
//! - `noise` — Noise_XX over TCP.

#![forbid(unsafe_code)]

pub mod keys;
pub mod kind;
pub mod transport;

pub use keys::NoiseIdentity;
pub use kind::NoiseTransportKind;
pub use transport::NoiseListener;
pub use transport::NoiseTransport;

use confium_net::register_transport;

register_transport!(NoiseTransportKind);
