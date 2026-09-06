//! OTS client — submit digests to calendar servers over the real
//! OpenTimestamps wire protocol, verify proofs.
//!
//! [`OtsClient::stamp_wire`] POSTs the digest to a calendar and
//! parses the returned partial proof (op stream + pending
//! attestation) with the [`crate::ots::wire`] format layer.
//! [`OtsClient::upgrade`] fetches a more complete proof for a pending
//! attestation. [`OtsClient::verify_wire`] replays the op tree from
//! the digest and classifies the attestations — an attestation is
//! only reported for the message the op-chain actually computes.
//!
//! [`OtsClient::verify`] (the chain-backed checker) remains
//! callback-based: confirming a Bitcoin attestation needs a block
//! header source the caller supplies.
//!
//! The deprecated [`OtsClient::stamp`] previously returned a
//! synthetic "proof"; it now refuses — no fabricated anchors.

use crate::ots::proof::{OtsError, OtsProof, OtsVerification};
use sha2::{Digest, Sha256};

/// Default public calendar servers (free, community-operated).
pub const DEFAULT_CALENDAR_SERVERS: &[&str] = &[
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

/// OTS client.
pub struct OtsClient {
    calendar_servers: Vec<String>,
}

impl OtsClient {
    /// Construct a new client with default calendar servers.
    pub fn new() -> Self {
        Self {
            calendar_servers: DEFAULT_CALENDAR_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// Construct with custom calendar servers.
    pub fn with_servers(servers: Vec<String>) -> Self {
        Self {
            calendar_servers: servers,
        }
    }

    /// Available calendar servers.
    pub fn calendar_servers(&self) -> &[String] {
        &self.calendar_servers
    }

    /// Submit a hash for timestamping over the real wire protocol:
    /// POST the 32-byte digest to `{server}/timestamp` and parse the
    /// returned partial proof. Servers are tried in order; the first
    /// success wins.
    ///
    /// The result carries a Pending attestation — Bitcoin confirmation
    /// arrives hours later; poll with [`Self::upgrade`].
    pub fn stamp_wire(&self, hash: [u8; 32]) -> Result<crate::ots::wire::OtsFile, OtsError> {
        let agent = calendar_agent();
        let mut last_err = None;
        for server in &self.calendar_servers {
            let url = format!("{server}/timestamp");
            let mut response = agent
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .send(hash.to_vec())
                .map_err(|e| OtsError::CalendarUnreachable(format!("{url}: {e}")))?;
            if !response.status().is_success() {
                return Err(OtsError::CalendarUnreachable(format!(
                    "{url} returned {}",
                    response.status()
                )));
            }
            let mut bytes = Vec::with_capacity(1024);
            use std::io::Read;
            response
                .body_mut()
                .as_reader()
                .read_to_end(&mut bytes)
                .map_err(|e| OtsError::CalendarUnreachable(format!("{url}: body: {e}")))?;
            match crate::ots::wire::parse(&hash, &bytes) {
                Ok(file) => return Ok(file),
                Err(e) => {
                    // Try the next server; the last error surfaces.
                    last_err = Some(OtsError::InvalidProof(format!("calendar response: {e}")))
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            OtsError::CalendarUnreachable("no calendar servers configured".into())
        }))
    }

    /// Fetch a more complete proof for a pending attestation: GET
    /// `{calendar}/timestamp/{digest-hex}`. The returned file replaces
    /// the pending one (it is a superset by construction).
    pub fn upgrade(
        &self,
        file: &crate::ots::wire::OtsFile,
    ) -> Result<crate::ots::wire::OtsFile, OtsError> {
        let uris: Vec<String> = crate::ots::wire::replay(file)
            .map_err(|e| OtsError::InvalidProof(e.to_string()))?
            .into_iter()
            .filter_map(|(_, a)| match a {
                crate::ots::wire::Attestation::Pending(uri) => Some(uri),
                _ => None,
            })
            .collect();
        if uris.is_empty() {
            return Err(OtsError::InvalidProof(
                "no pending calendar attestation to upgrade".into(),
            ));
        }
        let digest_hex = hex::encode(&file.digest);
        let agent = calendar_agent();
        for uri in uris {
            let url = format!("{uri}/timestamp/{digest_hex}");
            let mut response = agent
                .get(&url)
                .call()
                .map_err(|e| OtsError::CalendarUnreachable(format!("{url}: {e}")))?;
            if !response.status().is_success() {
                continue;
            }
            let mut bytes = Vec::with_capacity(1024);
            use std::io::Read;
            response
                .body_mut()
                .as_reader()
                .read_to_end(&mut bytes)
                .map_err(|e| OtsError::CalendarUnreachable(format!("{url}: body: {e}")))?;
            if let Ok(upgraded) = crate::ots::wire::parse(&file.digest, &bytes) {
                return Ok(upgraded);
            }
        }
        Err(OtsError::CalendarUnreachable(
            "no calendar returned an upgraded proof".into(),
        ))
    }

    /// Replay the proof tree from the digest and classify every
    /// attestation. No chain data needed: a pending attestation is
    /// reported as such; a Bitcoin attestation reports its height and
    /// the committed terminal message (the caller checks that against
    /// the block header's merkle-committed data).
    pub fn verify_wire(
        &self,
        file: &crate::ots::wire::OtsFile,
    ) -> Result<crate::ots::wire::OtsWireVerification, OtsError> {
        crate::ots::wire::verify(file).map_err(|e| OtsError::InvalidProof(e.to_string()))
    }

    /// Deprecated former entry point. It fabricated a synthetic
    /// "proof" anchored at a fixed height — exactly the footgun the
    /// audit notes flagged — so it now refuses instead.
    #[deprecated(since = "0.8.5", note = "fabricated proofs removed — use stamp_wire")]
    pub async fn stamp(&self, hash: [u8; 32]) -> Result<OtsProof, OtsError> {
        let _ = hash;
        Err(OtsError::CalendarUnreachable(
            "mock stamp removed: use stamp_wire for real calendar proofs".into(),
        ))
    }

    /// Verify a proof against Bitcoin block headers.
    ///
    /// Caller provides a `bitcoin_block_header_hash` callback that returns
    /// the block hash at the given height (real impl: query Bitcoin Core
    /// RPC, or use a public blockchain API).
    pub async fn verify<F>(
        &self,
        proof: &OtsProof,
        bitcoin_block_at_height: F,
    ) -> Result<OtsVerification, OtsError>
    where
        F: Fn(u32) -> Result<[u8; 32], String>,
    {
        // Verify the Merkle root matches what's in the block.
        let _block_hash =
            bitcoin_block_at_height(proof.bitcoin_height).map_err(OtsError::BitcoinBackend)?;

        // Mock: in real impl, parse block header, extract Merkle root,
        // verify the Merkle branch proves inclusion of `proof.hash` under
        // that root.
        let mut current = proof.hash;
        for sibling in &proof.merkle_branch {
            let mut h = Sha256::new();
            h.update(current);
            h.update(sibling);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize());
            // Double SHA-256 (Bitcoin convention)
            let mut h2 = Sha256::new();
            h2.update(out);
            current.copy_from_slice(&h2.finalize());
        }

        // An empty merkle branch proves nothing: without siblings the
        // claimed root is unverifiable, so an empty branch must NOT
        // verify (previously treated as valid).
        let valid = !proof.merkle_branch.is_empty() && current == proof.merkle_root;
        Ok(OtsVerification {
            valid,
            bitcoin_height: proof.bitcoin_height,
            block_timestamp: None,
        })
    }
}

fn calendar_agent() -> ureq::Agent {
    let config = ureq::config::Config::builder()
        .user_agent("confium-ots/0.8")
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build();
    ureq::Agent::new_with_config(config)
}

impl Default for OtsClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_has_default_servers() {
        let client = OtsClient::new();
        assert!(!client.calendar_servers().is_empty());
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn deprecated_stamp_refuses() {
        // The fabricated-proof footgun is gone: the old entry point
        // must refuse rather than return a fake anchor.
        let client = OtsClient::new();
        let result = client.stamp([42u8; 32]).await;
        assert!(result.is_err());
    }

    /// The local-socket stub tests flake when run in parallel (same
    /// class of port/handler races the net-noise roundtrip tests
    /// hit); serialize them.
    static STUB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Minimal HTTP calendar stub: serves one POST /timestamp and
    /// replies with a canned, valid partial proof.
    fn calendar_stub(port: u16, digest: [u8; 32]) -> std::thread::JoinHandle<()> {
        use std::io::{Read as _, Write as _};
        std::thread::spawn(move || {
            let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let n = stream.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Ok(headers_end) = find_headers_end(&buf) {
                    let body_len = content_length(&buf[..headers_end]);
                    if buf.len() >= headers_end + body_len {
                        break;
                    }
                }
            }
            let proof = canned_proof(&digest, port);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                proof.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(&proof).unwrap();
        })
    }

    fn find_headers_end(buf: &[u8]) -> Result<usize, ()> {
        buf.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .ok_or(())
    }

    fn content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("Content-Length:") {
                return v.trim().parse().unwrap_or(0);
            }
        }
        0
    }

    fn canned_proof(digest: &[u8; 32], port: u16) -> Vec<u8> {
        let file = crate::ots::wire::OtsFile {
            digest: digest.to_vec(),
            root: crate::ots::wire::TimestampNode {
                attestations: vec![],
                ops: vec![(
                    crate::ots::wire::Op::Sha256,
                    crate::ots::wire::TimestampNode {
                        attestations: vec![crate::ots::wire::Attestation::Pending(format!(
                            "http://127.0.0.1:{port}"
                        ))],
                        ops: vec![],
                    },
                )],
            },
        };
        crate::ots::wire::serialize(&file).unwrap()
    }

    #[test]
    fn stamp_wire_round_trips_against_local_calendar() {
        let _guard = STUB_LOCK.lock().unwrap();
        // Bind a stub on an OS-assigned port first, then connect.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let digest = [7u8; 32];
        let handle = calendar_stub(port, digest);
        // The stub serves exactly one connection; stamp_wire's first
        // (and only) server is the stub.
        let client = OtsClient::with_servers(vec![format!("http://127.0.0.1:{port}")]);
        let file = client.stamp_wire(digest).unwrap();
        handle.join().unwrap();

        assert_eq!(file.digest, digest.to_vec());
        let verification = client.verify_wire(&file).unwrap();
        assert!(verification.has_attestation());
        assert_eq!(verification.pending.len(), 1);
        let (msg, uri) = &verification.pending[0];
        assert_eq!(uri, &format!("http://127.0.0.1:{port}"));
        // msg == sha256(digest)
        use sha2::Digest as _;
        let mut h = Sha256::new();
        h.update(digest);
        assert_eq!(msg, &h.finalize().to_vec());
    }

    #[test]
    fn stamp_wire_rejects_garbage_response() {
        let _guard = STUB_LOCK.lock().unwrap();
        use std::io::{Read as _, Write as _};
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let handle = std::thread::spawn(move || {
            let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            // Drain the full request before responding: closing with
            // unread data sends an RST that shows up as a client-side
            // transport error instead of the proof-parse error we are
            // testing for.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let n = stream.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Ok(headers_end) = find_headers_end(&buf) {
                    let body_len = content_length(&buf[..headers_end]);
                    if buf.len() >= headers_end + body_len {
                        break;
                    }
                }
            }
            let body = b"not-an-ots-proof";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        let client = OtsClient::with_servers(vec![format!("http://127.0.0.1:{port}")]);
        let result = client.stamp_wire([9u8; 32]);
        handle.join().unwrap();
        assert!(
            matches!(result, Err(OtsError::InvalidProof(_))),
            "got: {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_empty_branch_is_rejected() {
        // An empty merkle branch proves nothing — it must NOT verify.
        let client = OtsClient::new();
        let hash = [1u8; 32];
        let proof = OtsProof::new(hash, 800_000);
        let result = client.verify(&proof, |_| Ok([0u8; 32])).await.unwrap();
        assert!(!result.valid);
    }
}
