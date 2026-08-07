//! TCP network protocol for coordinator ↔ signer communication.
//!
//! Wire format: 4-byte big-endian length prefix + JSON payload.
//!
//! Messages flow in both directions:
//! - Signer → Coordinator: Register, Commitment, Share
//! - Coordinator → Signer: Registered, SessionPending, CommitmentsReady, Signature
//! - Client → Coordinator: CreateSession, GetStatus
//! - Coordinator → Client: SessionCreated, Signature, Error

use crate::coordinator::session::SignerId;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::TcpStream;

/// Protocol message exchanged over TCP between coordinator, signers, and clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProtocolMessage {
    /// Signer registers with coordinator.
    Register {
        /// Signer identity.
        signer_id: SignerId,
        /// Quorum this signer belongs to.
        quorum_id: String,
    },
    /// Coordinator acknowledges registration.
    Registered {
        /// Signer identity.
        signer_id: SignerId,
    },
    /// Client requests session creation.
    CreateSession {
        /// Quorum ID.
        quorum_id: String,
        /// Signing scheme.
        scheme: String,
        /// Message to sign.
        message: Vec<u8>,
        /// Threshold T.
        threshold: u32,
        /// Total parties N.
        num_parties: u32,
    },
    /// Coordinator confirms session created.
    SessionCreated {
        /// Session ID.
        session_id: String,
    },
    /// Coordinator notifies signers of pending session.
    SessionPending {
        /// Session ID.
        session_id: String,
        /// Message to sign.
        message: Vec<u8>,
        /// Threshold.
        threshold: u32,
    },
    /// Signer submits commitment.
    Commitment {
        /// Session ID.
        session_id: String,
        /// Signer identity.
        signer_id: SignerId,
        /// Commitment bytes.
        bytes: Vec<u8>,
        /// Identity signature.
        signature: Vec<u8>,
    },
    /// Coordinator notifies that commitments are collected.
    CommitmentsReady {
        /// Session ID.
        session_id: String,
    },
    /// Signer submits share.
    Share {
        /// Session ID.
        session_id: String,
        /// Signer identity.
        signer_id: SignerId,
        /// Share bytes.
        bytes: Vec<u8>,
        /// Identity signature.
        signature: Vec<u8>,
    },
    /// Coordinator returns aggregated signature.
    Signature {
        /// Session ID.
        session_id: String,
        /// Signature bytes.
        bytes: Vec<u8>,
        /// Algorithm.
        algorithm: String,
        /// Contributing signers.
        contributing_signers: Vec<SignerId>,
    },
    /// Acknowledgement (commitment or share accepted, no further action needed).
    Ack {
        /// Session ID being acknowledged.
        session_id: String,
    },
    /// Error response.
    Error {
        /// Error message.
        message: String,
    },
    /// Status query.
    GetStatus {
        /// Session ID (optional).
        session_id: Option<String>,
    },
    /// Status response.
    Status {
        /// Session ID.
        session_id: String,
        /// Current state.
        state: String,
    },
    /// Liveness/readiness probe.
    HealthCheck,
    /// Health status response.
    HealthStatus {
        /// Server is running.
        alive: bool,
        /// Coordinator can accept sessions.
        ready: bool,
        /// Active session count.
        session_count: usize,
        /// Server uptime in seconds.
        uptime_seconds: u64,
    },
    /// Prometheus metrics query.
    MetricsQuery,
    /// Prometheus metrics response (text exposition format).
    MetricsResponse {
        /// Prometheus text format metrics.
        text: String,
    },
}

/// Send a protocol message over a TCP stream.
pub fn send_message(stream: &mut TcpStream, msg: &ProtocolMessage) -> io::Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&json)?;
    stream.flush()?;
    Ok(())
}

/// Receive a protocol message from a TCP stream.
pub fn recv_message(stream: &mut TcpStream) -> io::Result<ProtocolMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {} bytes", len),
        ));
    }

    let mut json_buf = vec![0u8; len];
    stream.read_exact(&mut json_buf)?;

    let msg: ProtocolMessage = serde_json::from_slice(&json_buf)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_message_serializes() {
        let msg = ProtocolMessage::Register {
            signer_id: "alice".into(),
            quorum_id: "test".into(),
        };
        let json = serde_json::to_vec(&msg).unwrap();
        assert!(json.len() > 10);
        let recovered: ProtocolMessage = serde_json::from_slice(&json).unwrap();
        match recovered {
            ProtocolMessage::Register {
                signer_id,
                quorum_id,
            } => {
                assert_eq!(signer_id, "alice");
                assert_eq!(quorum_id, "test");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn all_variants_round_trip() {
        let messages = vec![
            ProtocolMessage::Register {
                signer_id: "a".into(),
                quorum_id: "q".into(),
            },
            ProtocolMessage::Registered {
                signer_id: "a".into(),
            },
            ProtocolMessage::CreateSession {
                quorum_id: "q".into(),
                scheme: "FROST-P256".into(),
                message: vec![1, 2, 3],
                threshold: 3,
                num_parties: 5,
            },
            ProtocolMessage::SessionCreated {
                session_id: "s1".into(),
            },
            ProtocolMessage::SessionPending {
                session_id: "s1".into(),
                message: vec![1, 2, 3],
                threshold: 3,
            },
            ProtocolMessage::Commitment {
                session_id: "s1".into(),
                signer_id: "a".into(),
                bytes: vec![4, 5],
                signature: vec![6, 7],
            },
            ProtocolMessage::Signature {
                session_id: "s1".into(),
                bytes: vec![8, 9],
                algorithm: "FROST-P256".into(),
                contributing_signers: vec!["a".into(), "b".into()],
            },
            ProtocolMessage::Error {
                message: "test".into(),
            },
        ];
        for msg in &messages {
            let json = serde_json::to_vec(msg).unwrap();
            let recovered: ProtocolMessage = serde_json::from_slice(&json).unwrap();
            let json2 = serde_json::to_vec(&recovered).unwrap();
            assert_eq!(json, json2, "round-trip must preserve bytes");
        }
    }
}
