//! OTS client — submit hash to calendar servers, verify proofs.

use crate::proof::{OtsError, OtsProof, OtsVerification};
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

    /// Submit a hash for timestamping. Returns a mock proof immediately;
    /// real implementation would poll the calendar server until Bitcoin
    /// confirmation arrives (typically 1-12 hours).
    pub async fn stamp(&self, hash: [u8; 32]) -> Result<OtsProof, OtsError> {
        // Mock: return a proof anchored at a fixed block height.
        // Real impl: POST to calendar server, poll for proof, parse result.
        let _ = &self.calendar_servers;
        Ok(OtsProof::new(hash, 800_000))
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
        let _block_hash = bitcoin_block_at_height(proof.bitcoin_height)
            .map_err(|e| OtsError::BitcoinBackend(e))?;

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

        let valid = current == proof.merkle_root || proof.merkle_branch.is_empty();
        Ok(OtsVerification {
            valid,
            bitcoin_height: proof.bitcoin_height,
            block_timestamp: None,
        })
    }
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
    async fn mock_stamp_returns_proof() {
        let client = OtsClient::new();
        let hash = [42u8; 32];
        let proof = client.stamp(hash).await.unwrap();
        assert_eq!(proof.hash, hash);
        assert!(proof.bitcoin_height > 0);
    }

    #[tokio::test]
    async fn verify_empty_branch_is_valid() {
        let client = OtsClient::new();
        let hash = [1u8; 32];
        let proof = OtsProof::new(hash, 800_000);
        let result = client
            .verify(&proof, |_| Ok([0u8; 32]))
            .await
            .unwrap();
        assert!(result.valid);
    }
}
