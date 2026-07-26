//! CMS SignedData structure (RFC 5652).
//!
//! Provides idiomatic Rust types for CMS SignedData. Wire format is DER
//! (handled by the consumer via `der` crate when serializing for real
//! PKCS#7 compatibility). This crate provides the semantic model and
//! a simplified JSON serialization for testing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// SignedData structure as defined in RFC 5652 §5.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedData {
    /// CMS version (typically 1 for typical SignedData).
    pub version: u32,
    /// Digest algorithms used by signerInfos.
    pub digest_algorithms: Vec<AlgorithmIdentifier>,
    /// The encapsulated content (the payload being signed).
    pub encap_content_info: EncapContentInfo,
    /// Certificates (X.509) associated with the signers.
    pub certificates: Vec<Vec<u8>>,
    /// Signer info entries — one per signer.
    pub signer_infos: Vec<SignerInfo>,
}

/// Encapsulated content (the payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncapContentInfo {
    /// ContentType OID (e.g., "1.2.840.113549.1.7.1" for data).
    pub content_type: String,
    /// Optional content (absent for detached signatures).
    #[serde(default)]
    pub content: Option<Vec<u8>>,
}

/// Algorithm identifier (OID + optional parameters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID.
    pub oid: String,
    /// Optional parameters (raw bytes).
    #[serde(default)]
    pub parameters: Option<Vec<u8>>,
}

/// Signer information per RFC 5652 §5.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    /// CMS version (typically 1).
    pub version: u32,
    /// Signer identifier (typically issuerAndSerialNumber or subjectKeyIdentifier).
    pub sid: SignerIdentifier,
    /// Digest algorithm used.
    pub digest_algorithm: AlgorithmIdentifier,
    /// Signed attributes (optional).
    #[serde(default)]
    pub signed_attrs: Vec<Attribute>,
    /// Signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier,
    /// The signature bytes.
    pub signature: Vec<u8>,
    /// Unsigned attributes (optional).
    #[serde(default)]
    pub unsigned_attrs: Vec<Attribute>,
}

/// Signer identifier variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignerIdentifier {
    /// Issuer name + serial number.
    IssuerAndSerialNumber {
        /// Issuer name (DER-encoded).
        issuer_der: Vec<u8>,
        /// Certificate serial number.
        serial_number: Vec<u8>,
    },
    /// Subject key identifier.
    SubjectKeyIdentifier {
        /// Key identifier bytes.
        key_identifier: Vec<u8>,
    },
}

/// CMS attribute (OID + values).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    /// Attribute OID.
    pub oid: String,
    /// Attribute values (SET OF ANY).
    pub values: Vec<Vec<u8>>,
}

impl SignedData {
    /// Construct a new SignedData with the given encapsulated content.
    pub fn new(content_type: impl Into<String>, content: Option<Vec<u8>>) -> Self {
        Self {
            version: 1,
            digest_algorithms: Vec::new(),
            encap_content_info: EncapContentInfo {
                content_type: content_type.into(),
                content,
            },
            certificates: Vec::new(),
            signer_infos: Vec::new(),
        }
    }

    /// Add a signer.
    pub fn add_signer(&mut self, signer_info: SignerInfo) {
        // Add the digest algorithm to digest_algorithms if not present.
        let oid = &signer_info.digest_algorithm.oid;
        if !self.digest_algorithms.iter().any(|a| &a.oid == oid) {
            self.digest_algorithms.push(signer_info.digest_algorithm.clone());
        }
        self.signer_infos.push(signer_info);
    }

    /// Add a certificate (DER bytes).
    pub fn add_certificate(&mut self, cert_der: Vec<u8>) {
        self.certificates.push(cert_der);
    }

    /// Number of signers.
    pub fn signer_count(&self) -> usize {
        self.signer_infos.len()
    }

    /// When was this signed? (uses the first signer's signing time if available)
    pub fn signing_time(&self) -> Option<DateTime<Utc>> {
        self.signer_infos.first().and_then(|s| {
            s.signed_attrs.iter().find_map(|a| {
                if a.oid == "1.2.840.113549.1.9.5" {
                    // signingTime attribute — values[0] is UTCTime/GeneralizedTime DER
                    // For simplicity, return None; real impl would parse.
                    None
                } else {
                    None
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_data_construction() {
        let mut sd = SignedData::new("1.2.840.113549.1.7.1", Some(b"hello".to_vec()));
        let signer = SignerInfo {
            version: 1,
            sid: SignerIdentifier::SubjectKeyIdentifier {
                key_identifier: vec![1, 2, 3],
            },
            digest_algorithm: AlgorithmIdentifier {
                oid: "2.16.840.1.101.3.4.2.1".into(), // SHA-256
                parameters: None,
            },
            signed_attrs: Vec::new(),
            signature_algorithm: AlgorithmIdentifier {
                oid: "1.2.840.113549.1.1.11".into(), // sha256WithRSAEncryption
                parameters: None,
            },
            signature: vec![0u8; 256],
            unsigned_attrs: Vec::new(),
        };
        sd.add_signer(signer);
        sd.add_certificate(vec![0u8; 100]);
        assert_eq!(sd.signer_count(), 1);
        assert_eq!(sd.digest_algorithms.len(), 1);
        assert_eq!(sd.certificates.len(), 1);
    }
}
