//! TCP signer client — connects to coordinator, participates in signing sessions.
//!
//! Each signer:
//! 1. Connects to coordinator via TCP
//! 2. Registers with signer_id + quorum_id
//! 3. Creates a session (or receives notification of pending session)
//! 4. Submits commitment (round 1)
//! 5. Submits share (round 2)
//! 6. Receives aggregated signature (or error)
//!
//! Usage in e2e tests:
//! ```ignore
//! use confium_tc::coordinator::client::SignerClient;
//!
//! let mut client = SignerClient::connect("127.0.0.1:18432").unwrap();
//! client.register("director-1", "biml-root").unwrap();
//! client.submit_commitment("session-1", "director-1", &[0u8; 32]).unwrap();
//! client.submit_share("session-1", "director-1", &[0u8; 32]).unwrap();
//! ```

use std::io;
use std::net::TcpStream;

use crate::coordinator::net::ProtocolMessage;
use crate::coordinator::net::recv_message;
use crate::coordinator::net::send_message;
use crate::coordinator::net_server::SessionIo;

/// TCP signer client.
pub struct SignerClient {
    stream: Box<dyn SessionIo>,
}

impl SignerClient {
    /// Connect to coordinator at `addr` (e.g., "127.0.0.1:18432").
    pub fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self {
            stream: Box::new(stream),
        })
    }

    /// Connect over any registry transport URL — plain
    /// (`tcp://host:port`) or encrypted (`noise://host:port`, with
    /// optional `key=`/`pinned=` parameters). Link the transport
    /// crate (e.g. `confium-net-noise`) into the binary to enable
    /// its scheme.
    pub fn connect_url(url: &str) -> io::Result<Self> {
        let transport = confium_net::connect(url)
            .map_err(|e| io::Error::other(format!("connect {url}: {e}")))?;
        Ok(Self {
            stream: Box::new(confium_net::io::TransportIo::new(transport)),
        })
    }

    /// Register this signer with the coordinator.
    pub fn register(&mut self, signer_id: &str, quorum_id: &str) -> io::Result<()> {
        send_message(
            &mut self.stream,
            &ProtocolMessage::Register {
                signer_id: signer_id.into(),
                quorum_id: quorum_id.into(),
            },
        )?;
        let resp = recv_message(&mut self.stream)?;
        match resp {
            ProtocolMessage::Registered { signer_id: sid } if sid == signer_id => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected register response",
            )),
        }
    }

    /// Create a new signing session on the coordinator.
    pub fn create_session(
        &mut self,
        quorum_id: &str,
        scheme: &str,
        message: &[u8],
        threshold: u32,
        num_parties: u32,
    ) -> io::Result<String> {
        send_message(
            &mut self.stream,
            &ProtocolMessage::CreateSession {
                quorum_id: quorum_id.into(),
                scheme: scheme.into(),
                message: message.to_vec(),
                threshold,
                num_parties,
            },
        )?;
        let resp = recv_message(&mut self.stream)?;
        match resp {
            ProtocolMessage::SessionCreated { session_id } => Ok(session_id),
            ProtocolMessage::Error { message } => {
                Err(io::Error::other(format!("coordinator error: {message}")))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected response",
            )),
        }
    }

    /// Submit a commitment for a session.
    pub fn submit_commitment(
        &mut self,
        session_id: &str,
        signer_id: &str,
        commitment_bytes: &[u8],
    ) -> io::Result<()> {
        send_message(
            &mut self.stream,
            &ProtocolMessage::Commitment {
                session_id: session_id.into(),
                signer_id: signer_id.into(),
                bytes: commitment_bytes.to_vec(),
                signature: vec![0u8; 64],
            },
        )?;
        // Wait for Ack or Error
        self.stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)));
        match recv_message(&mut self.stream) {
            Ok(ProtocolMessage::Ack { .. }) => Ok(()),
            Ok(ProtocolMessage::Error { message }) => {
                Err(io::Error::other(format!("coordinator error: {message}")))
            }
            Ok(_) => Ok(()), // tolerate unexpected but non-error responses
            Err(e) => Err(e),
        }
    }

    /// Submit a share for a session. Returns the aggregated signature if
    /// this was the T-th share (threshold met).
    pub fn submit_share(
        &mut self,
        session_id: &str,
        signer_id: &str,
        share_bytes: &[u8],
    ) -> io::Result<Option<Vec<u8>>> {
        send_message(
            &mut self.stream,
            &ProtocolMessage::Share {
                session_id: session_id.into(),
                signer_id: signer_id.into(),
                bytes: share_bytes.to_vec(),
                signature: vec![0u8; 64],
            },
        )?;

        // Set a short read timeout — if coordinator doesn't respond (threshold
        // not met), the client gets WouldBlock instead of blocking forever.
        self.stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)));

        match recv_message(&mut self.stream) {
            Ok(ProtocolMessage::Signature { bytes, .. }) => Ok(Some(bytes)),
            Ok(ProtocolMessage::Ack { .. }) => Ok(None),
            Ok(ProtocolMessage::Error { message }) => {
                Err(io::Error::other(format!("coordinator error: {message}")))
            }
            Ok(_) => Ok(None),
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Query session status.
    pub fn get_status(&mut self, session_id: &str) -> io::Result<String> {
        send_message(
            &mut self.stream,
            &ProtocolMessage::GetStatus {
                session_id: Some(session_id.into()),
            },
        )?;
        let resp = recv_message(&mut self.stream)?;
        match resp {
            ProtocolMessage::Status { state, .. } => Ok(state),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected status response",
            )),
        }
    }

    /// Mutable access to the underlying session stream (TCP directly
    /// or a registry transport). Used by the signer daemon for
    /// low-level protocol message handling.
    pub fn stream_mut(&mut self) -> &mut Box<dyn SessionIo> {
        &mut self.stream
    }

    /// Receive the next protocol message on the session stream.
    pub fn recv(&mut self) -> io::Result<ProtocolMessage> {
        recv_message(self.stream.as_mut())
    }

    /// Send a protocol message on the session stream.
    pub fn send(&mut self, msg: &ProtocolMessage) -> io::Result<()> {
        send_message(self.stream.as_mut(), msg)
    }
}
