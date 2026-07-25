//! Deterministic mock transport.
//!
//! `mock://<name>` URLs address an in-memory mock transport whose
//! behavior is fully controlled by the test harness. Two peers sharing
//! a name exchange byte vectors through an internal channel (like
//! `inproc`), but the mock layer can be configured to:
//!
//! - **drop** messages (simulating a message-losing network or a
//!   Byzantine peer that withholds input),
//! - **tamper** messages (flipping bytes to simulate an active
//!   adversary),
//! - **record** every sent and received byte for post-hoc assertion.
//!
//! This is the transport for deterministic CI vectors and replay-attack
//! tests described in TODO #05.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::mpsc;

use url::Url;

use crate::Listener;
use crate::Result;
use crate::Transport;
use crate::error::ClosedSnafu;
use crate::error::MalformedUrlSnafu;
use crate::error::MockDropSnafu;
use crate::registry::TransportKind;

/// Global registry of named mock channel endpoints, mirroring the
/// inproc table. Each entry is a mailbox a connector pulls a handshake
/// out of.
static CHANNELS: OnceLock<Mutex<HashMap<String, mpsc::Sender<MockHandshake>>>> = OnceLock::new();

/// Per-channel behavior configuration. Both ends of a connection read
/// the same shared config so a harness can install fault-injection
/// rules before traffic flows.
static CONFIGS: OnceLock<Mutex<HashMap<String, MockConfig>>> = OnceLock::new();

fn channels() -> &'static Mutex<HashMap<String, mpsc::Sender<MockHandshake>>> {
    CHANNELS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn configs() -> &'static Mutex<HashMap<String, MockConfig>> {
    CONFIGS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Fault-injection knobs for a mock channel.
#[derive(Clone, Debug, Default)]
pub struct MockConfig {
    /// If `true`, every sent message is silently discarded and the
    /// receiver observes a [`crate::error::Error::MockDrop`].
    pub drop_all: bool,
    /// If `true`, every sent message has its bytes XORed with `0xFF`
    /// before delivery, simulating an active tampering adversary.
    pub tamper: bool,
}

impl MockConfig {
    /// Install a configuration for the named channel. Must be called
    /// before either end connects so both halves observe it.
    pub fn install(name: &str, cfg: MockConfig) {
        configs()
            .lock()
            .expect("mock config table poisoned")
            .insert(name.to_string(), cfg);
    }
}

struct MockHandshake {
    connector_to_peer: mpsc::Receiver<Vec<u8>>,
    peer_to_connector: mpsc::Sender<Vec<u8>>,
}

fn channel_name(url: &Url) -> Result<String> {
    let name = url.host_str().unwrap_or("");
    if name.is_empty() {
        return MalformedUrlSnafu {
            scheme: "mock",
            url: url.to_string(),
            reason: "missing channel name (use mock://<name>)",
        }
        .fail();
    }
    Ok(name.to_string())
}

fn config_for(name: &str) -> MockConfig {
    configs()
        .lock()
        .expect("mock config table poisoned")
        .get(name)
        .cloned()
        .unwrap_or_default()
}

/// Connected mock transport. All traffic is recorded for assertion.
pub struct MockTransport {
    tx: Option<mpsc::Sender<Vec<u8>>>,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    name: String,
    cfg: MockConfig,
    pending: Vec<u8>,
    /// Every byte sequence this end has sent, in order.
    pub sent_log: Vec<Vec<u8>>,
    /// Every byte sequence this end has received, in order.
    pub recv_log: Vec<Vec<u8>>,
}

impl MockTransport {
    fn new(
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
        name: String,
        cfg: MockConfig,
    ) -> Self {
        Self {
            tx: Some(tx),
            rx: Some(rx),
            name,
            cfg,
            pending: Vec::new(),
            sent_log: Vec::new(),
            recv_log: Vec::new(),
        }
    }

    /// The channel name this transport is bound to.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Transport for MockTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        self.sent_log.push(data.to_vec());
        if self.cfg.drop_all {
            // Drop is silent from the sender's perspective; the receiver
            // will see a MockDrop when it next tries to recv. We still
            // deliver a sentinel so the receiver can report the drop
            // deterministically rather than blocking forever.
            let tx = match &self.tx {
                Some(tx) => tx,
                None => return ClosedSnafu.fail(),
            };
            return tx.send(Vec::new()).map_err(|_| ClosedSnafu.build());
        }
        let mut payload = data.to_vec();
        if self.cfg.tamper {
            for byte in &mut payload {
                *byte ^= 0xFF;
            }
        }
        let tx = match &self.tx {
            Some(tx) => tx,
            None => return ClosedSnafu.fail(),
        };
        tx.send(payload).map_err(|_| ClosedSnafu.build())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.pending.is_empty() {
            let rx = match &self.rx {
                Some(rx) => rx,
                None => return ClosedSnafu.fail(),
            };
            let msg = rx.recv().map_err(|_| ClosedSnafu.build())?;
            if self.cfg.drop_all {
                return MockDropSnafu.fail();
            }
            self.recv_log.push(msg.clone());
            self.pending = msg;
        }
        let n = std::cmp::min(self.pending.len(), buf.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }

    fn close(&mut self) -> Result<()> {
        self.tx = None;
        self.rx = None;
        self.pending.clear();
        Ok(())
    }
}

pub struct MockListener {
    name: String,
    inbox: Option<mpsc::Receiver<MockHandshake>>,
}

impl MockListener {
    fn new(name: String, inbox: mpsc::Receiver<MockHandshake>) -> Self {
        Self {
            name,
            inbox: Some(inbox),
        }
    }
}

impl Listener for MockListener {
    fn accept(&mut self) -> Result<Box<dyn Transport>> {
        let inbox = match &self.inbox {
            Some(rx) => rx,
            None => return ClosedSnafu.fail(),
        };
        let handshake = inbox.recv().map_err(|_| ClosedSnafu.build())?;
        let cfg = config_for(&self.name);
        Ok(Box::new(MockTransport::new(
            handshake.peer_to_connector,
            handshake.connector_to_peer,
            self.name.clone(),
            cfg,
        )))
    }
}

impl Drop for MockListener {
    fn drop(&mut self) {
        if let Ok(mut table) = channels().lock() {
            table.remove(&self.name);
        }
    }
}

pub struct MockKind;

impl TransportKind for MockKind {
    fn schemes(&self) -> &'static [&'static str] {
        &["mock"]
    }

    fn connect(&self, url: &Url) -> Result<Box<dyn Transport>> {
        let name = channel_name(url)?;
        let tx = {
            let mut table = channels().lock().expect("mock channel table poisoned");
            match table.remove(&name) {
                Some(sender) => sender,
                None => {
                    return MalformedUrlSnafu {
                        scheme: "mock",
                        url: url.to_string(),
                        reason: "no listener registered for this channel name",
                    }
                    .fail();
                }
            }
        };
        let (c2p_tx, c2p_rx) = mpsc::channel::<Vec<u8>>();
        let (p2c_tx, p2c_rx) = mpsc::channel::<Vec<u8>>();
        tx.send(MockHandshake {
            connector_to_peer: c2p_rx,
            peer_to_connector: p2c_tx,
        })
        .map_err(|_| ClosedSnafu.build())?;
        let cfg = config_for(&name);
        Ok(Box::new(MockTransport::new(c2p_tx, p2c_rx, name, cfg)))
    }

    fn listen(&self, url: &Url) -> Result<Box<dyn Listener>> {
        let name = channel_name(url)?;
        let (handshake_tx, handshake_rx) = mpsc::channel::<MockHandshake>();
        let mut table = channels().lock().expect("mock channel table poisoned");
        if table.contains_key(&name) {
            return MalformedUrlSnafu {
                scheme: "mock",
                url: url.to_string(),
                reason: "channel name already in use",
            }
            .fail();
        }
        table.insert(name.clone(), handshake_tx);
        Ok(Box::new(MockListener::new(name, handshake_rx)))
    }
}

crate::register_transport!(MockKind);

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_name(tag: &str) -> String {
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering;
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        format!("mock-{tag}-{n}")
    }

    fn rendezvous(tag: &str) -> (Box<dyn Transport>, Box<dyn Transport>) {
        let name = unique_name(tag);
        let url = format!("mock://{name}");
        let mut listener = crate::listen(&url).unwrap();
        let client = crate::connect(&url).unwrap();
        let server = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn round_trip_preserves_order_and_payloads() {
        let (mut client, mut server) = rendezvous("rt");

        client.send(b"alpha").unwrap();
        client.send(b"beta").unwrap();

        let mut buf = [0u8; 16];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"alpha");
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"beta");
    }

    #[test]
    fn logs_record_traffic_for_directly_built_pair() {
        // Build a pair directly so we can inspect the concrete logs.
        let name = unique_name("log");
        let cfg = MockConfig::default();
        let (c2p_tx, c2p_rx) = mpsc::channel::<Vec<u8>>();
        let (p2c_tx, p2c_rx) = mpsc::channel::<Vec<u8>>();
        let mut client = MockTransport::new(c2p_tx, p2c_rx, name.clone(), cfg.clone());
        let mut server = MockTransport::new(p2c_tx, c2p_rx, name, cfg);

        client.send(b"one").unwrap();
        client.send(b"two").unwrap();

        let mut buf = [0u8; 16];
        let _ = server.recv(&mut buf).unwrap();
        let _ = server.recv(&mut buf).unwrap();

        assert_eq!(client.sent_log.len(), 2);
        assert_eq!(client.sent_log[0], b"one".to_vec());
        assert_eq!(client.sent_log[1], b"two".to_vec());
        assert_eq!(server.recv_log.len(), 2);
        assert_eq!(server.recv_log[0], b"one".to_vec());
        assert_eq!(server.recv_log[1], b"two".to_vec());
    }

    #[test]
    fn drop_config_silences_receiver() {
        let name = unique_name("drop");
        MockConfig::install(
            &name,
            MockConfig {
                drop_all: true,
                tamper: false,
            },
        );
        let url = format!("mock://{name}");
        let mut listener = crate::listen(&url).unwrap();
        let mut client = crate::connect(&url).unwrap();
        let mut server = listener.accept().unwrap();

        // Send succeeds (the harness intends to send); recv reports the
        // drop deterministically rather than blocking.
        client.send(b"lost").unwrap();
        let mut buf = [0u8; 16];
        let err = server.recv(&mut buf).unwrap_err();
        assert!(matches!(err, crate::error::Error::MockDrop { .. }));
    }

    #[test]
    fn tamper_config_corrupts_payload() {
        let name = unique_name("tamper");
        MockConfig::install(
            &name,
            MockConfig {
                drop_all: false,
                tamper: true,
            },
        );
        let url = format!("mock://{name}");
        let mut listener = crate::listen(&url).unwrap();
        let mut client = crate::connect(&url).unwrap();
        let mut server = listener.accept().unwrap();

        client.send(b"ABCDEFGH").unwrap();
        let mut buf = [0u8; 16];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(n, 8);
        // Every byte was XORed with 0xFF.
        let expected: Vec<u8> = b"ABCDEFGH".iter().map(|b| b ^ 0xFF).collect();
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn default_config_passes_payloads_through_unchanged() {
        let (mut client, mut server) = rendezvous("passthrough");
        client.send(b"plain").unwrap();
        let mut buf = [0u8; 16];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"plain");
    }
}
