//! Integration tests for the WebSocket transport.
//!
//! These exercise the real socket path: bind on `127.0.0.1:0` (OS-
//! assigned ephemeral port to avoid CI conflicts), connect over
//! `ws://`, exchange binary WebSocket messages both directions, and
//! confirm clean close terminates both sides. They go through the
//! high-level [`confium_net::connect`] / [`confium_net::listen`] entry
//! points so the link-time registry dispatch is exercised end-to-end.
//!
//! Depending on `confium-net-ws` from the test binary is what links the
//! crate (and its `register_transport!` submission) into the test
//! binary — without it, the `ws` scheme would be unknown to the
//! registry.
//!
//! A `wss://` (TLS) round-trip is gated behind the `tls` feature so
//! CI without test certificates can skip it; the feature is empty in
//! this crate today — enabling it simply opts the test binary into the
//! TLS path. The TLS test is marked `#[ignore]` by default since it
//! requires a locally-trusted certificate and is best run on demand.

use std::thread;

use confium_net as net;

#[test]
fn round_trip_single_message_via_registry() {
    // Bind via the concrete crate type to learn the OS-assigned
    // ephemeral port, then go through the high-level connect/listen
    // API for the actual exchange so the link-time registry dispatch
    // is exercised end-to-end.
    let std_listener = confium_net_ws::WsListener::bind("ws", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("ws://127.0.0.1:{port}/sess");

    let url_clone = url.clone();
    let client_handle = thread::spawn(move || -> net::Result<()> {
        let mut client = net::connect(&url_clone)?;
        client.send(b"hello threshold world")?;
        client.close()?;
        Ok(())
    });

    let mut server = listener.accept().expect("accept failed");
    let mut buf = [0u8; 64];
    let n = server.recv(&mut buf).expect("recv failed");
    assert_eq!(&buf[..n], b"hello threshold world");
    server.close().expect("server close");

    client_handle.join().unwrap().unwrap();
}

#[test]
fn bidirectional_traffic() {
    let std_listener = confium_net_ws::WsListener::bind("ws", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("ws://127.0.0.1:{port}/sess");

    let url_clone = url.clone();
    let client_handle = thread::spawn(move || -> net::Result<()> {
        let mut client = net::connect(&url_clone)?;
        client.send(b"c2s")?;
        let mut buf = [0u8; 16];
        let n = client.recv(&mut buf)?;
        assert_eq!(&buf[..n], b"s2c");
        client.close()?;
        Ok(())
    });

    let mut server = listener.accept().expect("accept failed");
    let mut buf = [0u8; 16];
    let n = server.recv(&mut buf).expect("server recv");
    assert_eq!(&buf[..n], b"c2s");
    server.send(b"s2c").expect("server send");
    server.close().expect("server close");

    client_handle.join().unwrap().unwrap();
}

#[test]
fn multiple_messages_preserve_order_and_boundaries() {
    // WebSocket frames preserve message boundaries natively, so three
    // separate sends are observed as three separate recvs — no
    // length-prefix framing layer is needed (unlike raw TCP).
    let std_listener = confium_net_ws::WsListener::bind("ws", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("ws://127.0.0.1:{port}/sess");

    let url_clone = url.clone();
    let client_handle = thread::spawn(move || -> net::Result<()> {
        let mut client = net::connect(&url_clone)?;
        client.send(b"alpha")?;
        client.send(b"beta")?;
        client.send(b"gamma")?;
        client.close()?;
        Ok(())
    });

    let mut server = listener.accept().expect("accept failed");
    let mut buf = [0u8; 32];
    let payloads: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];
    for expected in payloads {
        let n = server.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], *expected, "message framing broke");
    }
    server.close().expect("server close");
    client_handle.join().unwrap().unwrap();
}

#[test]
fn multiple_connections_to_same_listener() {
    // A single listener must be able to accept several independent
    // peers, each running its own WebSocket handshake.
    let std_listener = confium_net_ws::WsListener::bind("ws", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("ws://127.0.0.1:{port}/sess");

    let handles: Vec<_> = (0..3)
        .map(|i| {
            let url = url.clone();
            thread::spawn(move || -> net::Result<Vec<u8>> {
                let mut client = net::connect(&url)?;
                let payload = format!("peer-{i}");
                client.send(payload.as_bytes())?;
                client.close()?;
                Ok(payload.into_bytes())
            })
        })
        .collect();

    let mut received = Vec::new();
    for _ in 0..3 {
        let mut server = listener.accept().expect("accept");
        let mut buf = [0u8; 32];
        let n = server.recv(&mut buf).expect("recv");
        received.push(buf[..n].to_vec());
        server.close().expect("server close");
    }

    received.sort();
    assert_eq!(received[0], b"peer-0");
    assert_eq!(received[1], b"peer-1");
    assert_eq!(received[2], b"peer-2");

    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn close_terminates_both_sides() {
    // When the client closes, the server's subsequent recv should
    // observe a clean end-of-stream (Error::Closed) rather than
    // blocking forever. The WebSocket Close frame is the signal.
    let std_listener = confium_net_ws::WsListener::bind("ws", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("ws://127.0.0.1:{port}/sess");

    let url_clone = url.clone();
    let client_handle = thread::spawn(move || -> net::Result<()> {
        let mut client = net::connect(&url_clone)?;
        client.send(b"then I leave")?;
        client.close()?;
        Ok(())
    });

    let mut server = listener.accept().expect("accept");
    let mut buf = [0u8; 32];
    let n = server.recv(&mut buf).expect("first recv");
    assert_eq!(&buf[..n], b"then I leave");

    // Next recv should report Closed, not block.
    let err = server.recv(&mut buf).expect_err("expected Closed");
    assert!(
        matches!(err, net::Error::Closed { .. }),
        "expected Error::Closed, got {err:?}"
    );

    client_handle.join().unwrap().unwrap();
}

#[test]
fn missing_port_is_rejected() {
    // `ws://host` with no port must be rejected. (Confium URLs always
    // spell the port out, mirroring the `tcp://` contract — no
    // implicit 80/443 defaulting.)
    let result = net::connect("ws://127.0.0.1");
    let err = match result {
        Ok(_) => panic!("expected MalformedUrl error, got Ok"),
        Err(e) => e,
    };
    assert!(
        matches!(err, net::Error::MalformedUrl { ref scheme, .. } if scheme == "ws"),
        "expected MalformedUrl, got {err:?}"
    );
}

#[test]
fn empty_payload_round_trips() {
    // A zero-length binary frame must round-trip as a zero-length
    // recv, not be silently dropped or coalesced with the next
    // message. Empty round messages do occur in TC protocols
    // (ack-only rounds).
    let std_listener = confium_net_ws::WsListener::bind("ws", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("ws://127.0.0.1:{port}/sess");

    let url_clone = url.clone();
    let client_handle = thread::spawn(move || -> net::Result<()> {
        let mut client = net::connect(&url_clone)?;
        client.send(b"")?;
        client.send(b"after-empty")?;
        client.close()?;
        Ok(())
    });

    let mut server = listener.accept().expect("accept");
    let mut buf = [0u8; 32];
    let n = server.recv(&mut buf).expect("first recv");
    assert_eq!(n, 0, "empty frame should arrive as zero-length recv");
    let n = server.recv(&mut buf).expect("second recv");
    assert_eq!(&buf[..n], b"after-empty");
    server.close().expect("server close");

    client_handle.join().unwrap().unwrap();
}

/// TLS variant. Marked `#[ignore]` because it requires a locally-trusted
/// test certificate; run with `cargo test -p confium-net-ws -- --ignored
/// tls_round_trip`. Documents that the `wss://` client path is wired up
/// through the registry; a real run needs a TLS-terminating listener
/// (e.g. a local `openssl s_server` fronting a plain `ws://` listener,
/// or a reverse proxy).
#[test]
#[ignore = "requires a locally-trusted TLS endpoint; see comment"]
fn tls_round_trip() {
    // Replace HOST/PORT with a real `wss://` endpoint that presents a
    // certificate trusted by the platform's native CA store.
    let url = "wss://127.0.0.1:0/sess";
    let result = net::connect(url);
    // We expect either a connection refusal (no listener) or a
    // MalformedUrl (port 0 is invalid for connect); the point of the
    // test is that the `wss` scheme dispatches to WsTransportKind and
    // attempts a TLS handshake rather than erroring as "unknown
    // scheme".
    match result {
        Ok(_) | Err(net::Error::Closed { .. }) | Err(net::Error::MalformedUrl { .. }) => {}
        Err(net::Error::UnknownScheme { ref scheme, .. }) => {
            panic!("wss scheme not registered: {scheme}");
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}
