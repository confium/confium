//! Integration tests for the TCP transport.
//!
//! These exercise the real socket path: bind on `127.0.0.1:0` (OS-
//! assigned ephemeral port to avoid CI conflicts), connect, exchange
//! framed messages both directions, and confirm clean close terminates
//! both sides. They go through the high-level
//! [`confium_net::connect`] / [`confium_net::listen`] entry points so
//! the link-time registry dispatch is exercised end-to-end.
//!
//! Depending on `confium-net-tcp` from the test binary is what links
//! the crate (and its `register_transport!` submission) into the test
//! binary — without it, the `tcp` scheme would be unknown to the
//! registry.

use std::thread;

use confium_net as net;

#[test]
fn round_trip_single_message_via_registry() {
    // Bind via the concrete crate type to learn the OS-assigned
    // ephemeral port, then go through the high-level connect/listen API
    // for the actual exchange so the link-time registry dispatch is
    // exercised end-to-end.
    let std_listener =
        confium_net_tcp::TcpListener::bind("tcp", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("tcp://127.0.0.1:{port}");

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
    let std_listener =
        confium_net_tcp::TcpListener::bind("tcp", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("tcp://127.0.0.1:{port}");

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
    // Length-prefix framing means three separate sends are observed as
    // three separate recvs, not one coalesced byte blob. This is the
    // core property the framing layer exists to provide over a
    // byte-stream socket.
    let std_listener =
        confium_net_tcp::TcpListener::bind("tcp", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("tcp://127.0.0.1:{port}");

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
    // peers, each with its own framing state.
    let std_listener =
        confium_net_tcp::TcpListener::bind("tcp", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("tcp://127.0.0.1:{port}");

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
    // blocking forever.
    let std_listener =
        confium_net_tcp::TcpListener::bind("tcp", "127.0.0.1", 0).expect("bind failed");
    let port = std_listener.local_addr().expect("local_addr").port();
    let mut listener: Box<dyn net::Listener> = Box::new(std_listener);
    let url = format!("tcp://127.0.0.1:{port}");

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
    // `tcp://host` with no port must be rejected.
    let result = net::connect("tcp://127.0.0.1");
    let err = match result {
        Ok(_) => panic!("expected MalformedUrl error, got Ok"),
        Err(e) => e,
    };
    assert!(
        matches!(err, net::Error::MalformedUrl { ref scheme, .. } if scheme == "tcp"),
        "expected MalformedUrl, got {err:?}"
    );
}

#[test]
fn bind_failure_reports_the_os_error() {
    // The bind io error must survive as Error::Io (the previous
    // MalformedUrl mapping discarded it — WSAENOTSOCK on Windows was
    // invisible in gem CI logs, starving the diagnostic).
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port();
    let err = match net::listen(&format!("tcp://127.0.0.1:{port}")) {
        Ok(_) => panic!("expected bind failure, got Ok"),
        Err(e) => e,
    };
    assert!(
        matches!(err, net::Error::Io { .. }),
        "expected Error::Io, got {err:?}"
    );
    assert!(
        err.to_string().contains("os error"),
        "OS error code missing from: {err}"
    );
}

#[test]
fn connect_failure_reports_the_os_error() {
    // Nothing is listening on this port: connect must fail as Error::Io
    // with the OS error intact.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let err = match net::connect(&format!("tcp://127.0.0.1:{port}")) {
        Ok(_) => panic!("expected connect failure, got Ok"),
        Err(e) => e,
    };
    assert!(
        matches!(err, net::Error::Io { .. }),
        "expected Error::Io, got {err:?}"
    );
}
