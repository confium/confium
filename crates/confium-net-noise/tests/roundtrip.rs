//! End-to-end Noise transport tests over real loopback TCP.
//!
//! Tests serialize on a global lock: each binds a freshly probed
//! port and there is a probe-to-bind race if they run in parallel.

use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::thread;

use confium_net_noise::keys::NoiseIdentity;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let m = LOCK.get_or_init(|| Mutex::new(()));
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

fn listen_url(port: u16, key: Option<&NoiseIdentity>) -> String {
    match key {
        Some(k) => format!("noise://127.0.0.1:{port}?key={}", k.to_hex()),
        None => format!("noise://127.0.0.1:{port}"),
    }
}

/// Echo server: accept one noise connection, echo one message back.
/// The listener binds synchronously so the client can connect the
/// moment the handle exists.
fn spawn_echo(url: &str) -> thread::JoinHandle<()> {
    let mut listener = confium_net::listen(url).expect("noise listen");
    thread::spawn(move || {
        let mut conn = listener.accept().expect("noise accept");
        // Sized for the largest test payload: the Transport contract
        // fills what fits and drops the rest, like the built-in
        // inproc transport.
        let mut buf = vec![0u8; 1 << 20];
        let n = conn.recv(&mut buf).expect("server recv");
        conn.send(&buf[..n]).expect("server echo");
    })
}

#[test]
fn round_trip_through_the_registry() {
    let _guard = serial();
    let url = listen_url(free_port(), None);
    let server = spawn_echo(&url);

    let mut client = confium_net::connect(&url).expect("connect via registry");
    client.send(b"ping from client").unwrap();
    let mut buf = [0u8; 4096];
    let n = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping from client");
    server.join().unwrap();
}

#[test]
fn large_frame_round_trips() {
    let _guard = serial();
    let url = listen_url(free_port(), None);
    let server = spawn_echo(&url);

    // Well past snow's 65535-byte per-message cap: exercises the
    // fragmentation path (multiple encrypted chunks per payload).
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut client = confium_net::connect(&url).unwrap();
    client.send(&payload).unwrap();
    let mut buf = vec![0u8; payload.len()];
    let n = client.recv(&mut buf).unwrap();
    assert_eq!(n, payload.len());
    assert_eq!(buf, payload);
    server.join().unwrap();
}

#[test]
fn tiny_and_multi_payloads_round_trip() {
    let _guard = serial();
    let url = listen_url(free_port(), None);
    let server = {
        let mut listener = confium_net::listen(&url).unwrap();
        thread::spawn(move || {
            let mut conn = listener.accept().unwrap();
            let mut first = [0u8; 64];
            let mut second = [0u8; 64];
            let a = conn.recv(&mut first).unwrap();
            let b = conn.recv(&mut second).unwrap();
            let mut both = Vec::with_capacity(a + b);
            both.extend_from_slice(&first[..a]);
            both.extend_from_slice(&second[..b]);
            conn.send(&both).unwrap();
        })
    };
    let mut client = confium_net::connect(&url).unwrap();
    client.send(b"x").unwrap();
    client.send(b"yz").unwrap();
    let mut buf = [0u8; 64];
    let n = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"xyz");
    server.join().unwrap();
}

#[test]
fn pinned_fingerprint_mismatch_rejects_the_handshake() {
    let _guard = serial();
    let server_key = NoiseIdentity::generate();
    let url = listen_url(free_port(), Some(&server_key));
    let server = spawn_echo(&url);

    let wrong = [7u8; 32];
    let client_url = format!("{url}&pinned={}", hex(&wrong));
    let err = confium_net::connect(&client_url)
        .err()
        .map(|e| e.to_string())
        .expect("pinned connect must fail");
    assert!(
        err.contains("mismatch"),
        "expected pin mismatch, got: {err}"
    );
    // The echo thread unwinds when its handshake read hits the
    // client's abrupt close — join returning Err (panic) is fine.
    let _ = server.join();
}

#[test]
fn pinned_fingerprint_match_connects() {
    let _guard = serial();
    let server_key = NoiseIdentity::generate();
    let url = listen_url(free_port(), Some(&server_key));
    let server = spawn_echo(&url);

    let client_url = format!("{url}&pinned={}", hex(&server_key.fingerprint()));
    let mut client = confium_net::connect(&client_url).expect("pinned connect");
    client.send(b"hello").unwrap();
    let mut buf = [0u8; 16];
    let n = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello");
    server.join().unwrap();
}

#[test]
fn tampered_handshake_frame_aborts() {
    let _guard = serial();
    // Real responder on its own socket.
    let real_port = free_port();
    let real_url = format!("noise://127.0.0.1:{real_port}");
    let responder = {
        let mut listener = confium_net::listen(&real_url).unwrap();
        thread::spawn(move || {
            // The corrupted handshake must make accept fail; a
            // successful session would be the bug.
            if let Ok(_session) = listener.accept() {
                panic!("responder accepted a corrupted handshake");
            }
        })
    };

    // The tapper: the client dials the tapper; the tapper dials the
    // real responder and forwards the client's first handshake frame
    // with every payload byte flipped.
    let tap = TcpListener::bind("127.0.0.1:0").unwrap();
    let tap_port = tap.local_addr().unwrap().port();
    let tapper = thread::spawn(move || {
        let (mut client_side, _) = tap.accept().unwrap();
        let mut server_side = TcpStream::connect(("127.0.0.1", real_port)).unwrap();
        let mut prefix = [0u8; 4];
        client_side.read_exact(&mut prefix).unwrap();
        let len = u32::from_be_bytes(prefix) as usize;
        let mut frame = vec![0u8; len];
        client_side.read_exact(&mut frame).unwrap();
        for byte in frame.iter_mut() {
            *byte ^= 0x5A;
        }
        server_side.write_all(&prefix).unwrap();
        server_side.write_all(&frame).unwrap();
        // Hold both sides briefly so the failure is a decrypt error,
        // not a bare EOF.
        thread::sleep(std::time::Duration::from_millis(200));
    });

    let client_url = format!("noise://127.0.0.1:{tap_port}");
    match confium_net::connect(&client_url) {
        Ok(_session) => panic!("client completed a handshake over corrupted frames"),
        Err(_) => {} // expected: AEAD failure or aborted stream
    }
    tapper.join().unwrap();
    responder.join().unwrap();
}

#[test]
fn provisioned_identity_is_stable() {
    let _guard = serial();
    let id = NoiseIdentity::from_hex(&NoiseIdentity::generate().to_hex()).unwrap();
    let again = NoiseIdentity::from_hex(&id.to_hex()).unwrap();
    assert_eq!(id.fingerprint(), again.fingerprint());
}
