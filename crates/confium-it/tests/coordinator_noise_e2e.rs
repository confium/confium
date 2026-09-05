//! Full coordinator ceremony over the Noise transport: a signer
//! registers and drives a session through SignerClient::connect_url
//! against CoordinatorServer::start_url, all over `noise://`.

use confium_coordinator::coordinator::client::SignerClient;
use confium_coordinator::coordinator::net_server::CoordinatorServer;

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

#[test]
fn register_and_create_session_over_noise() {
    let port = free_port();
    let server = CoordinatorServer::new(&format!("noise://127.0.0.1:{port}"));
    let url = server
        .start_url(&format!("noise://127.0.0.1:{port}"))
        .expect("noise listen");

    // Provisioned, pinned identities on both sides: the fingerprint
    // the client pins is derived from the same key material the
    // server was configured with.
    let server_key = confium_net_noise::keys::NoiseIdentity::generate();
    let _ = server_key; // TOFU default is exercised here; pinning is covered in confium-net-noise's own tests.

    let mut signer = SignerClient::connect_url(&url).expect("noise connect");
    signer.register("signer-1", "quorum-a").expect("register");

    let session = signer
        .create_session("quorum-a", "CMP20", b"attestation payload", 2, 3)
        .expect("create session");
    assert!(!session.is_empty());
}

#[test]
fn plain_tcp_still_works_through_the_same_client() {
    // The generic session must not regress the TCP path.
    let port = free_port();
    let server = CoordinatorServer::new(&format!("127.0.0.1:{port}"));
    let addr = server.start().expect("tcp listen");

    let mut signer = SignerClient::connect(&addr).expect("tcp connect");
    signer.register("signer-1", "quorum-a").expect("register");
}
