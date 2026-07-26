//! CMS envelope construction.
//!
//! Builds a SignedData envelope from a payload, signer, and optional
//! certificate chain. For DER-encoded output compatible with OpenSSL,
//! Thunderbird/RNP, etc., the consumer should serialize via the `der`
//! crate (not done here — this crate provides the semantic model only).

use crate::cms::signed_data::{
    AlgorithmIdentifier, EncapContentInfo, SignedData, SignerIdentifier, SignerInfo,
};

/// Builder for `SignedData`.
#[derive(Debug, Default)]
pub struct SignedDataBuilder {
    content_type: Option<String>,
    content: Option<Vec<u8>>,
    signers: Vec<SignerInfo>,
    certificates: Vec<Vec<u8>>,
}

impl SignedDataBuilder {
    /// Construct a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the encapsulated content type OID.
    pub fn content_type(mut self, oid: impl Into<String>) -> Self {
        self.content_type = Some(oid.into());
        self
    }

    /// Set the encapsulated content (None = detached signature).
    pub fn content(mut self, content: Option<Vec<u8>>) -> Self {
        self.content = content;
        self
    }

    /// Add a signer.
    pub fn signer(mut self, signer: SignerInfo) -> Self {
        self.signers.push(signer);
        self
    }

    /// Add a certificate (DER bytes).
    pub fn certificate(mut self, cert_der: Vec<u8>) -> Self {
        self.certificates.push(cert_der);
        self
    }

    /// Build the SignedData.
    pub fn build(self) -> Result<SignedData, CmsError> {
        let content_type = self
            .content_type
            .ok_or(CmsError::MissingField("content_type"))?;
        let mut sd = SignedData::new(content_type, self.content);
        for cert in self.certificates {
            sd.add_certificate(cert);
        }
        for signer in self.signers {
            sd.add_signer(signer);
        }
        Ok(sd)
    }
}

/// Errors during CMS envelope construction.
#[derive(Debug, thiserror::Error)]
pub enum CmsError {
    /// Required field missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Serialization failure.
    #[error("serialization error: {0}")]
    Serialize(String),
    /// Verification failure.
    #[error("verification failure: {0}")]
    Verify(String),
    /// JSON encode/decode error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience: build a minimal detached CMS signature with one signer.
pub fn build_detached_signature(
    payload_hash: Vec<u8>,
    signer_algorithm: impl Into<String>,
    signature: Vec<u8>,
    cert_chain_der: Vec<Vec<u8>>,
) -> Result<SignedData, CmsError> {
    let _ = payload_hash; // payload hash goes in signedAttrs (real impl); skipped here
    let signer = SignerInfo {
        version: 1,
        sid: SignerIdentifier::SubjectKeyIdentifier {
            key_identifier: cert_chain_der
                .first()
                .map(|c| c[..20].to_vec())
                .unwrap_or_default(),
        },
        digest_algorithm: AlgorithmIdentifier {
            oid: "2.16.840.1.101.3.4.2.1".into(), // SHA-256
            parameters: None,
        },
        signed_attrs: Vec::new(),
        signature_algorithm: AlgorithmIdentifier {
            oid: signer_algorithm.into(),
            parameters: None,
        },
        signature,
        unsigned_attrs: Vec::new(),
    };
    let mut builder = SignedDataBuilder::new()
        .content_type("1.2.840.113549.1.7.1")
        .content(None)
        .signer(signer);
    for cert in cert_chain_der {
        builder = builder.certificate(cert);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_constructs_signed_data() {
        let sd = SignedDataBuilder::new()
            .content_type("1.2.840.113549.1.7.1")
            .content(Some(b"hello".to_vec()))
            .build()
            .unwrap();
        assert_eq!(sd.encap_content_info.content_type, "1.2.840.113549.1.7.1");
        assert_eq!(sd.encap_content_info.content, Some(b"hello".to_vec()));
    }

    #[test]
    fn detached_signature_helper() {
        let sd = build_detached_signature(
            vec![0u8; 32],
            "1.2.840.113549.1.1.11",
            vec![0u8; 256],
            vec![vec![0u8; 100]],
        )
        .unwrap();
        assert_eq!(sd.signer_count(), 1);
        assert!(sd.encap_content_info.content.is_none()); // detached
    }

    #[test]
    fn missing_content_type_fails() {
        let result = SignedDataBuilder::new().build();
        assert!(result.is_err());
    }
}

/// Re-export EncapContentInfo so consumers can build it without reaching
/// into the signed_data module directly.
pub use crate::cms::signed_data::EncapContentInfo as _ReExportEncapContentInfo;
