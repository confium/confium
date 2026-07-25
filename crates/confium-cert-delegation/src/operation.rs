//! Operations that can be delegated.

use serde::{Deserialize, Serialize};

/// An operation that a delegated child cert is authorized to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    /// Sign another certificate (CA-style delegation).
    SignCert(SignCertSpec),
    /// Sign a document (XMLDSig, CMS, raw).
    SignDocument(SignDocSpec),
    /// Threshold-sign a message (participate in a quorum).
    ThresholdSign(ThresholdSignSpec),
    /// Encrypt a payload to a recipient (e.g., for sealed archival).
    Encrypt(EncryptSpec),
}

/// Spec for `SignCert` operations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignCertSpec {
    /// Permitted certificate types (e.g., "instance-cert", "sub-ca-cert").
    pub permitted_cert_types: Vec<String>,
}

/// Spec for `SignDocument` operations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignDocSpec {
    /// Permitted document MIME types.
    pub permitted_mime_types: Vec<String>,
    /// Permitted signature formats.
    pub permitted_formats: Vec<SignatureFormat>,
}

/// Permitted signature format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFormat {
    /// Raw signature bytes.
    Raw,
    /// CMS / PKCS#7 SignedData.
    Cms,
    /// XMLDSig.
    Xmldsig,
    /// JWS (JSON Web Signature).
    Jws,
    /// COSE (CBOR Object Signing and Encryption).
    Cose,
}

/// Spec for `ThresholdSign` operations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThresholdSignSpec {
    /// Permitted schemes (e.g., "FROST-ed25519", "CMP20-P256").
    pub permitted_schemes: Vec<String>,
}

/// Spec for `Encrypt` operations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EncryptSpec {
    /// Permitted recipient quorums (by quorum ID).
    pub permitted_recipients: Vec<String>,
}
