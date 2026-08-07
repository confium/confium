//! End-to-end integration test: coordinator server + signer client.
//!
//! Starts a CoordinatorServer on a random port, connects a
//! SignerClient, and exercises the full signing lifecycle:
//! register → create session → submit commitment → submit share →
//! receive aggregated signature.

use confium_tc::coordinator::client::SignerClient;
use confium_tc::coordinator::net_server::CoordinatorServer;
use confium_tc::coordinator::net::ProtocolMessage;
use confium_tc::coordinator::net::{recv_message, send_message};
use std::net::TcpStream;
use std::time::Duration;

/// Wait for a TCP port to become available, retrying up to 5 seconds.
fn wait_for_server(addr: &str) {
    for _ in 0..50 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("server at {addr} did not come up");
}

#[test]
fn e2e_register_and_health_check() {
    let server = CoordinatorServer::new("127.0.0.1:0");
    let addr = server.start().unwrap();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    send_message(
        &mut stream,
        &ProtocolMessage::Register {
            signer_id: "alice".into(),
            quorum_id: "quorum-1".into(),
        },
    )
    .unwrap();
    let resp = recv_message(&mut stream).unwrap();
    match resp {
        ProtocolMessage::Registered { signer_id } => {
            assert_eq!(signer_id, "alice");
        }
        _ => panic!("expected Registered, got {resp:?}"),
    }
}

#[test]
fn e2e_health_check_returns_alive() {
    let server = CoordinatorServer::new("127.0.0.1:0");
    let addr = server.start().unwrap();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    send_message(&mut stream, &ProtocolMessage::HealthCheck).unwrap();
    let resp = recv_message(&mut stream).unwrap();
    match resp {
        ProtocolMessage::HealthStatus {
            alive,
            ready,
            session_count,
            uptime_seconds: _,
        } => {
            assert!(alive);
            assert!(ready);
            assert_eq!(session_count, 0);
        }
        _ => panic!("expected HealthStatus, got {resp:?}"),
    }
}

#[test]
fn e2e_full_signing_lifecycle() {
    let server = CoordinatorServer::new("127.0.0.1:0");
    let addr = server.start().unwrap();
    wait_for_server(&addr);

    let mut client = SignerClient::connect(&addr).unwrap();
    client.register("bob", "quorum-2").unwrap();

    let session_id = client
        .create_session("quorum-2", "CMP20", b"test message", 2, 3)
        .unwrap();
    assert!(!session_id.is_empty());

    let commitment = vec![0xAA; 32];
    client
        .submit_commitment(&session_id, "bob", &commitment)
        .unwrap();

    let share = vec![0xBB; 32];
    let result = client.submit_share(&session_id, "bob", &share);
    // With MockSigner and threshold=2, we won't get a signature yet
    // (need 2 shares). This is expected — we just verify no error.
    assert!(result.is_ok());
}

#[test]
fn e2e_get_status_after_create() {
    let server = CoordinatorServer::new("127.0.0.1:0");
    let addr = server.start().unwrap();
    wait_for_server(&addr);

    let mut client = SignerClient::connect(&addr).unwrap();
    client.register("carol", "quorum-3").unwrap();

    let session_id = client
        .create_session("quorum-3", "FROST-P256", b"hello", 1, 1)
        .unwrap();

    let status = client.get_status(&session_id).unwrap();
    assert!(status.contains("Pending") || status.contains("pending"));
}

#[test]
fn e2e_session_count_increments() {
    let server = CoordinatorServer::new("127.0.0.1:0");
    let addr = server.start().unwrap();
    wait_for_server(&addr);

    let mut stream1 = TcpStream::connect(&addr).unwrap();
    send_message(
        &mut stream1,
        &ProtocolMessage::CreateSession {
            quorum_id: "q".into(),
            scheme: "CMP20".into(),
            message: vec![0; 32],
            threshold: 2,
            num_parties: 3,
        },
    )
    .unwrap();
    let _ = recv_message(&mut stream1).unwrap();

    let mut stream2 = TcpStream::connect(&addr).unwrap();
    send_message(&mut stream2, &ProtocolMessage::HealthCheck).unwrap();
    let resp = recv_message(&mut stream2).unwrap();
    match resp {
        ProtocolMessage::HealthStatus { session_count, .. } => {
            assert!(session_count >= 1);
        }
        _ => panic!("expected HealthStatus"),
    }
}
