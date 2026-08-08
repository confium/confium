//! TCP coordinator server — wraps the in-memory Coordinator with a TCP server.
//!
//! Listens on a TCP port. Each client connection gets its own thread.
//! Routes protocol messages to the Coordinator's API.

use std::io;
use std::net::{TcpListener, TcpStream};
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
}

impl CoordinatorServer {
    /// Create a new server bound to `addr` (e.g., "127.0.0.1:0" for random port).
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            coordinator: Arc::new(Mutex::new(Coordinator::new())),
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

        thread::spawn(move || {
            for stream_result in listener.incoming() {
                match stream_result {
                    Ok(stream) => {
                        let coord = Arc::clone(&coordinator);
                        thread::spawn(move || {
                            let _ = handle_connection(stream, coord);
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
}

fn handle_connection(mut stream: TcpStream, coordinator: SharedCoordinator) -> io::Result<()> {
    loop {
        let msg = match recv_message(&mut stream) {
            Ok(m) => m,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(_) => break,
        };

        let response = process_message(msg, &coordinator);
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
                    // After each share, try to aggregate
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

        ProtocolMessage::HealthCheck => Some(ProtocolMessage::HealthStatus {
            alive: true,
            ready: true,
            session_count: coordinator.lock().unwrap().session_count(),
            uptime_seconds: 0,
        }),

        _ => Some(ProtocolMessage::Error {
            message: "unexpected message type".into(),
        }),
    }
}
