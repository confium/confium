//! Transport abstraction for authenticated encryption.
//!
//! OCP: new transport types (Noise, TLS, QUIC) implement [`Transport`]
//! without modifying the coordinator or signer daemon.

use std::io::{Read, Write};

/// Transport mode — client or server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Client,
    Server,
}

/// A secure transport for coordinator↔signer communication.
pub trait Transport: Read + Write + Send {
    /// Transport name (e.g., "plaintext", "noise", "tls").
    fn name(&self) -> &str;
    /// Whether the connection is encrypted.
    fn is_encrypted(&self) -> bool;
    /// Peer identity (authenticated ID or None).
    fn peer_identity(&self) -> Option<String>;
}

/// Plaintext transport (no encryption — development only).
pub struct PlaintextTransport {
    inner: std::net::TcpStream,
    peer: Option<String>,
}

impl PlaintextTransport {
    pub fn new(stream: std::net::TcpStream) -> Self {
        let peer = stream
            .peer_addr()
            .ok()
            .map(|a| a.to_string());
        Self { inner: stream, peer }
    }
}

impl Read for PlaintextTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for PlaintextTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Transport for PlaintextTransport {
    fn name(&self) -> &str {
        "plaintext"
    }
    fn is_encrypted(&self) -> bool {
        false
    }
    fn peer_identity(&self) -> Option<String> {
        self.peer.clone()
    }
}

/// Transport factory trait — produces transports for connections.
pub trait TransportFactory: Send + Sync {
    /// Wrap a raw TCP stream into a transport.
    fn wrap(&self, stream: std::net::TcpStream, mode: TransportMode) -> Box<dyn Transport>;
    /// Factory name.
    fn name(&self) -> &str;
}

/// Plaintext factory (development).
pub struct PlaintextTransportFactory;

impl TransportFactory for PlaintextTransportFactory {
    fn wrap(&self, stream: std::net::TcpStream, _mode: TransportMode) -> Box<dyn Transport> {
        Box::new(PlaintextTransport::new(stream))
    }
    fn name(&self) -> &str {
        "plaintext"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_not_encrypted() {
        let factory = PlaintextTransportFactory;
        // Can't actually connect, but can verify the factory name
        assert_eq!(factory.name(), "plaintext");
    }

    #[test]
    fn transport_mode_eq() {
        assert_eq!(TransportMode::Client, TransportMode::Client);
        assert_ne!(TransportMode::Client, TransportMode::Server);
    }

    #[test]
    fn factory_implements_trait() {
        let factory: Box<dyn TransportFactory> = Box::new(PlaintextTransportFactory);
        assert_eq!(factory.name(), "plaintext");
    }
}
