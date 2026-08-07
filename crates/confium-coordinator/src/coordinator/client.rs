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
//! ```no_run
//! use confium_tc::coordinator::client::SignerClient;
//!
//! let mut client = SignerClient::connect("127.0.0.1:18432").unwrap();
//! client.register("director-1", "biml-root").unwrap();
//! client.submit_commitment("session-1", "director-1", &[0u8; 32]).unwrap();
//! client.submit_share("session-1", "director-1", &[0u8; 32]).unwrap();
//! ```

use std::io;
use std::net::TcpStream;

use crate::coordinator::net::{ProtocolMessage, recv_message, send_message};

/// TCP signer client.
pub struct SignerClient {
    stream: TcpStream,
}

impl SignerClient {
    /// Connect to coordinator at `addr` (e.g., "127.0.0.1:18432").
    pub fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self { stream })
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
            ProtocolMessage::Error { message } => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("coordinator error: {message}"),
            )),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        match recv_message(&mut self.stream) {
            Ok(ProtocolMessage::Ack { .. }) => Ok(()),
            Ok(ProtocolMessage::Error { message }) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("coordinator error: {message}"),
            )),
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
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        match recv_message(&mut self.stream) {
            Ok(ProtocolMessage::Signature { bytes, .. }) => Ok(Some(bytes)),
            Ok(ProtocolMessage::Ack { .. }) => Ok(None),
            Ok(ProtocolMessage::Error { message }) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("coordinator error: {message}"),
            )),
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

    /// Get a mutable reference to the underlying TCP stream. Used by
    /// the signer daemon for low-level protocol message handling.
    pub fn stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}
