//! TLS 1.3 signature callback satisfying via threshold.
//!
//! For high-value TLS endpoints (root CAs, payment gateways), the
//! server signing key is threshold-held across multiple data centers.
//! This crate provides the TLS callback that routes the signature
//! request through a Confium coordinator.
//!
//! See `TODO.roadmap/28-mode2-pki-replacement.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// TLS signature scheme identifier (RFC 8446 §4.2.3 SignatureScheme).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum SignatureScheme {
    /// ECDSA over NIST P-256 with SHA-256 (0x0403).
    EcdsaSecp256r1Sha256 = 0x0403,
    /// Ed25519 (0x0807).
    Ed25519 = 0x0807,
    /// RSA PKCS#1 v1.5 with SHA-256 (0x0401).
    RsaPkcs1Sha256 = 0x0401,
    /// RSA-PSS with SHA-256 (0x0804).
    RsaPssSha256 = 0x0804,
}

/// TLS signature request from the TLS handshake layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSignatureRequest {
    /// Signature scheme to use.
    pub scheme: SignatureScheme,
    /// Data to be signed (typically the handshake transcript hash).
    pub data: Vec<u8>,
    /// Quorum that holds the threshold signing key.
    pub quorum_id: String,
}

/// TLS signature response — the produced signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSignatureResponse {
    /// Signature scheme used.
    pub scheme: SignatureScheme,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// Errors during TLS signing.
#[derive(Debug, thiserror::Error)]
pub enum TlsSignerError {
    /// Unsupported signature scheme.
    #[error("unsupported signature scheme: {0:?}")]
    UnsupportedScheme(SignatureScheme),
    /// Threshold signing failed.
    #[error("threshold signing failed: {0}")]
    ThresholdFailed(String),
    /// Coordinator unreachable.
    #[error("coordinator unreachable: {0}")]
    CoordinatorUnreachable(String),
    /// Timeout waiting for quorum.
    #[error("timeout waiting for T-of-N quorum")]
    QuorumTimeout,
}

/// Signer hook — caller provides concrete threshold signing backend.
pub trait ThresholdSigner {
    /// Sign `data` using the quorum's threshold key.
    fn sign(&self, quorum_id: &str, scheme: SignatureScheme, data: &[u8]) -> Result<Vec<u8>, String>;
}

/// The TLS signer.
pub struct TlsSigner<'a> {
    signer: &'a dyn ThresholdSigner,
}

impl<'a> TlsSigner<'a> {
    /// Construct a new TLS signer backed by `signer`.
    pub fn new(signer: &'a dyn ThresholdSigner) -> Self {
        Self { signer }
    }

    /// Handle a TLS signature request.
    pub fn sign(
        &self,
        request: &TlsSignatureRequest,
    ) -> Result<TlsSignatureResponse, TlsSignerError> {
        let signature = self
            .signer
            .sign(&request.quorum_id, request.scheme, &request.data)
            .map_err(TlsSignerError::ThresholdFailed)?;
        Ok(TlsSignatureResponse {
            scheme: request.scheme,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSigner;
    impl ThresholdSigner for MockSigner {
        fn sign(
            &self,
            _quorum_id: &str,
            _scheme: SignatureScheme,
            data: &[u8],
        ) -> Result<Vec<u8>, String> {
            Ok(data.to_vec())
        }
    }

    #[test]
    fn tls_sign_mock_round_trip() {
        let signer = MockSigner;
        let tls = TlsSigner::new(&signer);
        let req = TlsSignatureRequest {
            scheme: SignatureScheme::Ed25519,
            data: b"handshake transcript".to_vec(),
            quorum_id: "test-quorum".into(),
        };
        let resp = tls.sign(&req).unwrap();
        assert_eq!(resp.scheme, SignatureScheme::Ed25519);
        assert_eq!(resp.signature, req.data);
    }
}
