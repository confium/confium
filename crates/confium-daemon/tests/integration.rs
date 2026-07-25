//! Integration test: spin up confiumd on an ephemeral TCP port, send a
//! JSON-RPC `version()` request, and assert the response carries the
//! daemon's version.
//!
//! This is the end-to-end smoke test required by TODO.roadmap/16.
//!
//! All tests run inside a [`tokio::task::LocalSet`] because the
//! Confium engine holds `Rc<dyn Any>` plugin interfaces, making it
//! `!Send`. The server's connection handling must stay on one thread.

use std::rc::Rc;

use confium_daemon::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::LocalSet;

/// Send one length-prefixed JSON-RPC message and read one
/// length-prefixed response.
async fn rpc_call(stream: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await.unwrap();
    resp
}

#[tokio::test]
async fn version_round_trip_over_tcp() {
    LocalSet::new()
        .run_until(async {
            // Bind to port 0 so the OS picks an ephemeral port.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Start the server (LocalSet is already entered by
            // run_until, so spawn_local works inside run_tcp).
            let server = Rc::new(Server::new());
            let server_handle = tokio::task::spawn_local(async move {
                let _ = server.run_tcp(listener).await;
            });

            // Connect a client and call version().
            let mut client = TcpStream::connect(addr).await.unwrap();
            let req = br#"{"jsonrpc":"2.0","id":1,"method":"version","params":{}}"#;
            let resp_bytes = rpc_call(&mut client, req).await;

            let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
            assert_eq!(resp["jsonrpc"], "2.0");
            assert_eq!(resp["id"], 1);
            assert_eq!(resp["result"]["version"], env!("CARGO_PKG_VERSION"));

            server_handle.abort();
        })
        .await;
}

#[tokio::test]
async fn unknown_method_returns_error_over_tcp() {
    LocalSet::new()
        .run_until(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server = Rc::new(Server::new());
            let server_handle = tokio::task::spawn_local(async move {
                let _ = server.run_tcp(listener).await;
            });

            let mut client = TcpStream::connect(addr).await.unwrap();
            let req = br#"{"jsonrpc":"2.0","id":2,"method":"nonexistent_method","params":{}}"#;
            let resp_bytes = rpc_call(&mut client, req).await;

            let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
            assert_eq!(resp["jsonrpc"], "2.0");
            assert_eq!(resp["id"], 2);
            // Method not found = JSON-RPC code -32601
            assert_eq!(resp["error"]["code"], -32601);
            assert!(
                resp["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("nonexistent_method")
            );

            server_handle.abort();
        })
        .await;
}

#[tokio::test]
async fn shutdown_stops_the_server() {
    LocalSet::new()
        .run_until(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server = Rc::new(Server::new());
            let server_handle = tokio::task::spawn_local(async move {
                let _ = server.run_tcp(listener).await;
            });

            // Send shutdown.
            let mut client = TcpStream::connect(addr).await.unwrap();
            let req = br#"{"jsonrpc":"2.0","id":3,"method":"shutdown","params":{}}"#;
            let resp_bytes = rpc_call(&mut client, req).await;

            let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
            assert_eq!(resp["result"]["ok"], true);

            // The server task should complete shortly after shutdown.
            let result =
                tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
            assert!(result.is_ok(), "server did not shut down within 2s");
        })
        .await;
}
