//! In-process transport.
//!
//! `inproc://<name>` URLs address a named, in-memory channel. A
//! [`InprocListener`] registered under a name accepts connections from
//! [`InprocTransport`] peers that `connect` to the same name. Each
//! accepted connection is a pair of [`std::sync::mpsc`] channels
//! carrying owned byte vectors, giving a reliable, ordered, single-use
//! byte stream.
//!
//! This transport exists for tests and single-process threshold-
//! cryptography simulation — multiple party state machines running in
//! one binary, exchanging protocol rounds through loopback channels.

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
use crate::registry::TransportKind;

/// Global, process-wide table of named inproc listening endpoints.
///
/// A listener registers a `Sender<InprocHandshake>` here under its URL
/// name; a connector pulls a matching receiver out to complete the
/// rendezvous. The table is lazy-initialized on first use.
static LISTENERS: OnceLock<Mutex<HashMap<String, mpsc::Sender<InprocHandshake>>>> = OnceLock::new();

fn listeners() -> &'static Mutex<HashMap<String, mpsc::Sender<InprocHandshake>>> {
    LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One half of a freshly established inproc connection. The connector
/// receives the pair of channels it will use to talk to the accepted
/// peer.
struct InprocHandshake {
    /// Channel the connector writes into and the accepted peer reads
    /// from.
    connector_to_peer: mpsc::Receiver<Vec<u8>>,
    /// Channel the accepted peer writes into and the connector reads
    /// from.
    peer_to_connector: mpsc::Sender<Vec<u8>>,
}

/// Extract the channel name from an `inproc://` URL.
fn channel_name(url: &Url) -> Result<String> {
    let name = url.host_str().unwrap_or("");
    if name.is_empty() {
        return MalformedUrlSnafu {
            scheme: "inproc",
            url: url.to_string(),
            reason: "missing channel name (use inproc://<name>)",
        }
        .fail();
    }
    Ok(name.to_string())
}

/// Connected in-process transport. Messages are framed as owned
/// `Vec<u8>`; `send` pushes one, `recv` pops one into the caller's
/// buffer.
pub struct InprocTransport {
    tx: Option<mpsc::Sender<Vec<u8>>>,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// Bytes from the current message not yet drained into the caller's
    /// buffer; the remainder is held until the next `recv`.
    pending: Vec<u8>,
}

impl InprocTransport {
    fn new(tx: mpsc::Sender<Vec<u8>>, rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            tx: Some(tx),
            rx: Some(rx),
            pending: Vec::new(),
        }
    }
}

impl Transport for InprocTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        match &self.tx {
            Some(tx) => tx.send(data.to_vec()).map_err(|_| ClosedSnafu.build()),
            None => ClosedSnafu.fail(),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.pending.is_empty() {
            let rx = match &self.rx {
                Some(rx) => rx,
                None => return ClosedSnafu.fail(),
            };
            let msg = rx.recv().map_err(|_| ClosedSnafu.build())?;
            self.pending = msg;
        }
        let n = std::cmp::min(self.pending.len(), buf.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        // If the caller's buffer was too small for the whole message,
        // drop the remainder — inproc messages are atomic units (one
        // `send` == one `recv` payload) and partial framing across
        // calls would surprise callers. The dropped bytes are reported
        // back via the returned count; a stricter buffer-too-small
        // error is reserved for transports that preserve framing.
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

/// Listening endpoint for `inproc://` connections.
///
/// Holding this alive keeps the named channel registered in the global
/// table; dropping it unregisters the name.
pub struct InprocListener {
    name: String,
    inbox: Option<mpsc::Receiver<InprocHandshake>>,
}

impl InprocListener {
    fn new(name: String, inbox: mpsc::Receiver<InprocHandshake>) -> Self {
        Self {
            name,
            inbox: Some(inbox),
        }
    }
}

impl Listener for InprocListener {
    fn accept(&mut self) -> Result<Box<dyn Transport>> {
        let inbox = match &self.inbox {
            Some(rx) => rx,
            None => return ClosedSnafu.fail(),
        };
        let handshake = inbox.recv().map_err(|_| ClosedSnafu.build())?;
        Ok(Box::new(InprocTransport::new(
            handshake.peer_to_connector,
            handshake.connector_to_peer,
        )))
    }
}

impl Drop for InprocListener {
    fn drop(&mut self) {
        if let Ok(mut table) = listeners().lock() {
            table.remove(&self.name);
        }
    }
}

/// Registry kind for the in-process transport.
pub struct InprocKind;

impl TransportKind for InprocKind {
    fn schemes(&self) -> &'static [&'static str] {
        &["inproc"]
    }

    fn connect(&self, url: &Url) -> Result<Box<dyn Transport>> {
        let name = channel_name(url)?;
        let tx = {
            let mut table = listeners().lock().expect("inproc listener table poisoned");
            match table.remove(&name) {
                Some(sender) => sender,
                None => {
                    return MalformedUrlSnafu {
                        scheme: "inproc",
                        url: url.to_string(),
                        reason: "no listener registered for this channel name",
                    }
                    .fail();
                }
            }
        };
        let (connector_to_peer_tx, connector_to_peer_rx) = mpsc::channel::<Vec<u8>>();
        let (peer_to_connector_tx, peer_to_connector_rx) = mpsc::channel::<Vec<u8>>();
        tx.send(InprocHandshake {
            connector_to_peer: connector_to_peer_rx,
            peer_to_connector: peer_to_connector_tx,
        })
        .map_err(|_| ClosedSnafu.build())?;
        Ok(Box::new(InprocTransport::new(
            connector_to_peer_tx,
            peer_to_connector_rx,
        )))
    }

    fn listen(&self, url: &Url) -> Result<Box<dyn Listener>> {
        let name = channel_name(url)?;
        let (handshake_tx, handshake_rx) = mpsc::channel::<InprocHandshake>();
        let mut table = listeners().lock().expect("inproc listener table poisoned");
        if table.contains_key(&name) {
            return MalformedUrlSnafu {
                scheme: "inproc",
                url: url.to_string(),
                reason: "channel name already in use",
            }
            .fail();
        }
        table.insert(name.clone(), handshake_tx);
        Ok(Box::new(InprocListener::new(name, handshake_rx)))
    }
}

crate::register_transport!(InprocKind);

#[cfg(test)]
mod tests {
    /// Use a unique name per test to avoid collisions in the global
    /// table, since inventory registration is process-wide and tests
    /// run in the same binary.
    fn unique_name(tag: &str) -> String {
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering;
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        format!("test-{tag}-{n}")
    }

    #[test]
    fn round_trip_single_message() {
        let name = unique_name("rt");
        let url = format!("inproc://{name}");
        let mut listener = crate::listen(&url).unwrap();
        // Listener must exist before connect consumes it from the table.
        let mut client = crate::connect(&url).unwrap();
        let mut server = listener.accept().unwrap();

        let payload = b"hello threshold world";
        client.send(payload).unwrap();
        let mut buf = [0u8; 64];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn bidirectional_traffic() {
        let name = unique_name("bi");
        let url = format!("inproc://{name}");
        let mut listener = crate::listen(&url).unwrap();
        let mut client = crate::connect(&url).unwrap();
        let mut server = listener.accept().unwrap();

        client.send(b"c2s").unwrap();
        server.send(b"s2c").unwrap();

        let mut buf = [0u8; 16];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"c2s");
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"s2c");
    }

    #[test]
    fn recv_after_close_reports_closed() {
        let name = unique_name("close");
        let url = format!("inproc://{name}");
        let mut listener = crate::listen(&url).unwrap();
        let mut client = crate::connect(&url).unwrap();
        let mut server = listener.accept().unwrap();

        client.close().unwrap();
        let mut buf = [0u8; 16];
        let err = server.recv(&mut buf).unwrap_err();
        assert!(matches!(err, crate::error::Error::Closed { .. }));
    }

    #[test]
    fn connect_without_listener_fails() {
        let url = "inproc://no-such-channel-zzz";
        let err = crate::connect(url).err().unwrap();
        assert!(matches!(
            err,
            crate::error::Error::MalformedUrl { scheme, .. } if scheme == "inproc"
        ));
    }

    #[test]
    fn listen_twice_same_name_collides() {
        let name = unique_name("collide");
        let url = format!("inproc://{name}");
        let _l1 = crate::listen(&url).unwrap();
        let err = crate::listen(&url).err().unwrap();
        assert!(matches!(
            err,
            crate::error::Error::MalformedUrl { scheme, reason, .. }
                if scheme == "inproc" && reason.contains("already in use")
        ));
    }
}
