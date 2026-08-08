//! Signer daemon — connects to coordinator and responds to signing requests.

use crate::config::DaemonConfig;
use confium_coordinator::coordinator::client::SignerClient;
use confium_coordinator::coordinator::net::{ProtocolMessage, recv_message, send_message};
use std::io;
use std::path::Path;

/// The running daemon. Manages the coordinator connection and
/// responds to signing requests.
pub struct SignerDaemon {
    config: DaemonConfig,
}

impl SignerDaemon {
    /// Create a new daemon from configuration.
    pub fn new(config: DaemonConfig) -> Self {
        Self { config }
    }

    /// Connect to the coordinator, register, and enter the main loop.
    /// Returns when the connection drops and retries are exhausted.
    pub fn run(&self) -> RunResult {
        let mut attempts = 0u32;
        loop {
            tracing::info!(
                addr = %self.config.coordinator_addr,
                attempt = attempts,
                "connecting to coordinator"
            );
            match self.connect_and_serve() {
                Ok(()) => return RunResult::Disconnected,
                Err(e) => {
                    tracing::warn!(error = %e, "connection lost");
                    attempts += 1;
                    let max = self.config.max_reconnect_attempts;
                    if max > 0 && attempts >= max {
                        tracing::error!(attempts, "max reconnect attempts reached, giving up");
                        return RunResult::MaxRetriesExhausted;
                    }
                    let backoff = self.config.reconnect_backoff_secs;
                    tracing::info!(backoff_secs = backoff, "sleeping before reconnect");
                    std::thread::sleep(std::time::Duration::from_secs(backoff));
                }
            }
        }
    }

    fn connect_and_serve(&self) -> io::Result<()> {
        let mut client = SignerClient::connect(&self.config.coordinator_addr)?;
        client.register(&self.config.signer_id, &self.config.quorum_id)?;
        tracing::info!(signer_id = %self.config.signer_id, "registered with coordinator");

        let share_bytes = self.load_share()?;

        loop {
            let msg = recv_message(client.stream())?;
            match msg {
                ProtocolMessage::SessionPending {
                    session_id,
                    message,
                    threshold: _,
                } => {
                    tracing::info!(session = %session_id, "received signing request");
                    self.handle_signing_request(
                        client.stream(),
                        &session_id,
                        &message,
                        &share_bytes,
                    )?;
                }
                ProtocolMessage::HealthCheck => {
                    send_message(
                        client.stream(),
                        &ProtocolMessage::HealthStatus {
                            alive: true,
                            ready: true,
                            session_count: 0,
                            uptime_seconds: 0,
                        },
                    )?;
                }
                _ => {
                    tracing::debug!(msg = ?msg, "ignoring unexpected message");
                }
            }
        }
    }

    fn handle_signing_request(
        &self,
        stream: &mut std::net::TcpStream,
        session_id: &str,
        _message: &[u8],
        share_bytes: &[u8],
    ) -> io::Result<()> {
        let commitment = self.derive_commitment(share_bytes);
        send_message(
            stream,
            &ProtocolMessage::Commitment {
                session_id: session_id.into(),
                signer_id: self.config.signer_id.clone(),
                bytes: commitment,
                signature: vec![0u8; 64],
            },
        )?;
        let _ = recv_message(stream)?;

        send_message(
            stream,
            &ProtocolMessage::Share {
                session_id: session_id.into(),
                signer_id: self.config.signer_id.clone(),
                bytes: share_bytes.to_vec(),
                signature: vec![0u8; 64],
            },
        )?;

        match recv_message(stream) {
            Ok(ProtocolMessage::Signature { bytes, .. }) => {
                tracing::info!(
                    session = session_id,
                    sig_len = bytes.len(),
                    "signature aggregated"
                );
            }
            Ok(ProtocolMessage::Ack { .. }) => {
                tracing::info!(
                    session = session_id,
                    "share submitted, waiting for more signers"
                );
            }
            Ok(ProtocolMessage::Error { message }) => {
                tracing::error!(session = session_id, error = %message, "signing failed");
            }
            _ => {}
        }
        Ok(())
    }

    fn derive_commitment(&self, share_bytes: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(share_bytes);
        hasher.update(self.config.signer_id.as_bytes());
        hasher.update(&[0u8; 8]);
        hasher.finalize().to_vec()
    }

    fn load_share(&self) -> io::Result<Vec<u8>> {
        let path = Path::new(&self.config.share_file);
        std::fs::read(path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("share file {}: {e}", path.display()),
            )
        })
    }
}

/// Why the daemon stopped.
#[derive(Debug)]
pub enum RunResult {
    /// Connection ended cleanly.
    Disconnected,
    /// All reconnect attempts failed.
    MaxRetriesExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_config() -> DaemonConfig {
        DaemonConfig {
            coordinator_addr: "127.0.0.1:0".into(),
            signer_id: "test-signer".into(),
            quorum_id: "test-quorum".into(),
            share_file: "/dev/null".into(),
            scheme: "CMP20".into(),
            reconnect_backoff_secs: 1,
            max_reconnect_attempts: 1,
        }
    }

    #[test]
    fn daemon_constructs_from_config() {
        let config = make_config();
        let daemon = SignerDaemon::new(config);
        assert_eq!(daemon.config.signer_id, "test-signer");
    }

    #[test]
    fn derive_commitment_is_deterministic() {
        let config = make_config();
        let daemon = SignerDaemon::new(config);
        let share = vec![0xAA; 32];
        let c1 = daemon.derive_commitment(&share);
        let c2 = daemon.derive_commitment(&share);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 32);
    }

    #[test]
    fn derive_commitment_differs_for_different_shares() {
        let config = make_config();
        let daemon = SignerDaemon::new(config);
        let c1 = daemon.derive_commitment(&[0xAA; 32]);
        let c2 = daemon.derive_commitment(&[0xBB; 32]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn load_share_reads_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&[0x42; 64]).unwrap();
        let mut config = make_config();
        config.share_file = tmp.path().to_string_lossy().to_string();
        let daemon = SignerDaemon::new(config);
        let share = daemon.load_share().unwrap();
        assert_eq!(share, vec![0x42; 64]);
    }

    #[test]
    fn load_share_missing_file_errors() {
        let mut config = make_config();
        config.share_file = "/nonexistent/path/share.json".into();
        let daemon = SignerDaemon::new(config);
        assert!(daemon.load_share().is_err());
    }
}
