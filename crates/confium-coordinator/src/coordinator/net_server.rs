//! TCP coordinator server — wraps the in-memory Coordinator with a TCP server.
//!
//! Listens on a TCP port. Each client connection gets its own thread.
//! Routes protocol messages to the Coordinator's API.

use std::io;
use std::net::TcpListener;
use std::net::TcpStream;

/// A byte-stream session: TCP directly, or any registry transport
/// (e.g. noise) wrapped in [`confium_net::io::TransportIo`].
pub trait SessionIo: std::io::Read + std::io::Write + Send {
    /// Best-effort read timeout. Returns `false` when unsupported
    /// (non-socket transports are message-framed and their `recv`
    /// blocks only for the next message, which is the desired
    /// behavior for a caller that previously set a socket timeout).
    fn set_read_timeout(&mut self, _d: Option<std::time::Duration>) -> bool {
        false
    }
}

impl SessionIo for TcpStream {
    fn set_read_timeout(&mut self, d: Option<std::time::Duration>) -> bool {
        std::net::TcpStream::set_read_timeout(self, d).is_ok()
    }
}

impl SessionIo for confium_net::io::TransportIo {}
use std::sync::{Arc, Mutex};
use std::thread;

use crate::coordinator::coordinator::Coordinator;
use crate::coordinator::net::{ProtocolMessage, recv_message, send_message};
use crate::coordinator::session::{Commitment, Share};
use chrono::Utc;

/// Thread-safe coordinator shared across connection handlers.
pub type SharedCoordinator = Arc<Mutex<Coordinator>>;

/// TCP coordinator server.
pub struct CoordinatorServer {
    addr: String,
    coordinator: SharedCoordinator,
    start_time: std::time::Instant,
}

impl CoordinatorServer {
    /// Create a new server bound to `addr` (e.g., "127.0.0.1:0" for random port).
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            coordinator: Arc::new(Mutex::new(Coordinator::new())),
            start_time: std::time::Instant::now(),
        }
    }

    /// Get the shared coordinator handle.
    pub fn shared_coordinator(&self) -> SharedCoordinator {
        Arc::clone(&self.coordinator)
    }

    /// Start the server in a background thread. Returns the actual bound address.
    pub fn start(&self) -> io::Result<String> {
        let listener = TcpListener::bind(&self.addr)?;
        let bound_addr = listener.local_addr()?.to_string();
        let coordinator = Arc::clone(&self.coordinator);
        let start_time = self.start_time;

        thread::spawn(move || {
            for stream_result in listener.incoming() {
                match stream_result {
                    Ok(stream) => {
                        let coord = Arc::clone(&coordinator);
                        thread::spawn(move || {
                            let _ = handle_connection(
                                Box::new(stream) as Box<dyn SessionIo>,
                                coord,
                                start_time,
                            );
                        });
                    }
                    Err(e) => {
                        eprintln!("Coordinator: accept error: {e}");
                    }
                }
            }
        });

        Ok(bound_addr)
    }

    /// Serve sessions over any registry transport URL (e.g.
    /// `noise://0.0.0.0:18432?key=<hex>`). The scheme resolves at
    /// link time; link `confium-net-noise` (or another transport
    /// crate) into the binary to make it available.
    pub fn start_url(&self, url: &str) -> io::Result<String> {
        let mut listener =
            confium_net::listen(url).map_err(|e| io::Error::other(format!("listen {url}: {e}")))?;
        let coordinator = Arc::clone(&self.coordinator);
        let start_time = self.start_time;

        thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok(transport) => {
                        let coord = Arc::clone(&coordinator);
                        thread::spawn(move || {
                            let session = confium_net::io::TransportIo::new(transport);
                            let _ = handle_connection(
                                Box::new(session) as Box<dyn SessionIo>,
                                coord,
                                start_time,
                            );
                        });
                    }
                    Err(e) => {
                        eprintln!("Coordinator: accept error: {e}");
                    }
                }
            }
        });

        Ok(url.to_string())
    }
}

fn handle_connection(
    mut stream: Box<dyn SessionIo>,
    coordinator: SharedCoordinator,
    start_time: std::time::Instant,
) -> io::Result<()> {
    loop {
        let msg = match recv_message(&mut stream) {
            Ok(m) => m,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(_) => break,
        };

        let response = process_message(msg, &coordinator, start_time);
        if let Some(resp) = response {
            if send_message(&mut stream, &resp).is_err() {
                break;
            }
        }
    }
    Ok(())
}

fn process_message(
    msg: ProtocolMessage,
    coordinator: &SharedCoordinator,
    start_time: std::time::Instant,
) -> Option<ProtocolMessage> {
    match msg {
        ProtocolMessage::Register {
            signer_id,
            quorum_id: _,
        } => Some(ProtocolMessage::Registered {
            signer_id: signer_id.clone(),
        }),

        ProtocolMessage::CreateSession {
            quorum_id,
            scheme,
            message,
            threshold,
            num_parties,
        } => {
            let mut coord = coordinator.lock().unwrap();
            let request = crate::coordinator::session::SessionRequest {
                quorum_id,
                scheme,
                message,
                threshold,
                num_parties,
                unlock_window_minutes: 240,
                requested_by: "tcp-client".into(),
            };
            match coord.create_session(request) {
                Ok(session_id) => Some(ProtocolMessage::SessionCreated { session_id }),
                Err(e) => Some(ProtocolMessage::Error {
                    message: format!("{e:?}"),
                }),
            }
        }

        ProtocolMessage::Commitment {
            session_id,
            signer_id,
            bytes,
            signature,
        } => {
            let mut coord = coordinator.lock().unwrap();
            let commitment = Commitment {
                signer_id: signer_id.clone(),
                bytes,
                signer_signature: signature,
                submitted_at: Utc::now(),
            };
            match coord.submit_commitment(&session_id, commitment) {
                Ok(()) => Some(ProtocolMessage::Ack { session_id }),
                Err(e) => Some(ProtocolMessage::Error {
                    message: format!("{e:?}"),
                }),
            }
        }

        ProtocolMessage::Share {
            session_id,
            signer_id,
            bytes,
            signature,
        } => {
            let mut coord = coordinator.lock().unwrap();
            let share = Share {
                signer_id: signer_id.clone(),
                bytes,
                signer_signature: signature,
                submitted_at: Utc::now(),
            };
            match coord.submit_share(&session_id, share) {
                Ok(()) => {
                    let threshold = coord.session_threshold(&session_id).unwrap_or(0);
                    let share_count = coord.session_share_count(&session_id).unwrap_or(0);
                    if share_count >= threshold as usize {
                        match coord.aggregate(&session_id) {
                            Ok(sig) => Some(ProtocolMessage::Signature {
                                session_id: session_id.clone(),
                                bytes: sig.bytes,
                                algorithm: sig.algorithm,
                                contributing_signers: sig.contributing_signers,
                            }),
                            Err(e) => Some(ProtocolMessage::Error {
                                message: format!("{e:?}"),
                            }),
                        }
                    } else {
                        Some(ProtocolMessage::Ack { session_id })
                    }
                }
                Err(e) => Some(ProtocolMessage::Error {
                    message: format!("{e:?}"),
                }),
            }
        }

        ProtocolMessage::GetStatus { session_id } => {
            let coord = coordinator.lock().unwrap();
            match session_id {
                Some(sid) => {
                    let state = coord.session_state(&sid);
                    Some(ProtocolMessage::Status {
                        session_id: sid,
                        state: format!("{:?}", state),
                    })
                }
                None => Some(ProtocolMessage::Error {
                    message: "session_id required".into(),
                }),
            }
        }

        ProtocolMessage::HealthCheck => {
            let coord = coordinator.lock().unwrap();
            let session_count = coord.session_count();
            Some(ProtocolMessage::HealthStatus {
                alive: true,
                ready: true,
                session_count,
                uptime_seconds: start_time.elapsed().as_secs(),
            })
        }

        _ => Some(ProtocolMessage::Error {
            message: "unexpected message type".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_returns_status() {
        let server = CoordinatorServer::new("127.0.0.1:0");
        let coordinator = server.shared_coordinator();
        let start_time = server.start_time;

        let response = process_message(ProtocolMessage::HealthCheck, &coordinator, start_time);
        match response {
            Some(ProtocolMessage::HealthStatus {
                alive,
                ready,
                session_count,
                uptime_seconds,
            }) => {
                assert!(alive);
                assert!(ready);
                assert_eq!(session_count, 0);
                assert!(uptime_seconds < 5);
            }
            _ => panic!("expected HealthStatus"),
        }
    }

    #[test]
    fn health_check_after_session_increments_count() {
        let server = CoordinatorServer::new("127.0.0.1:0");
        let coordinator = server.shared_coordinator();
        let start_time = server.start_time;

        let req = crate::coordinator::session::SessionRequest {
            quorum_id: "q1".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold: 2,
            num_parties: 3,
            unlock_window_minutes: 60,
            requested_by: "test".into(),
        };
        coordinator.lock().unwrap().create_session(req).unwrap();

        let response = process_message(ProtocolMessage::HealthCheck, &coordinator, start_time);
        match response {
            Some(ProtocolMessage::HealthStatus { session_count, .. }) => {
                assert_eq!(session_count, 1);
            }
            _ => panic!("expected HealthStatus"),
        }
    }
}
