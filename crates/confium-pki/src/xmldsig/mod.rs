//! XMLDSig and Exclusive C14N for XML document signing.
//!
//! Produces standard XMLDSig signatures verifiable by `xmlsec1`, browser-
//! native XMLDSig, and existing OIML CNML verifiers. Direct integration
//! point with the CNML project.
//!
//! See `TODO.roadmap/32-cert-delegation-cms-xmldsig.md` for full spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod c14n;

pub use c14n::*;

use serde::{Deserialize, Serialize};

/// Canonicalization algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Canonicalization {
    /// Exclusive XML Canonicalization (default for XMLDSig).
    ExclusiveC14N,
    /// Exclusive C14N with comments.
    ExclusiveC14NWithComments,
    /// Inclusive XML Canonicalization.
    InclusiveC14N,
    /// Inclusive C14N with comments.
    InclusiveC14NWithComments,
}

impl Canonicalization {
    /// W3C algorithm identifier.
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            Canonicalization::ExclusiveC14N => "http://www.w3.org/2001/10/xml-exc-c14n#",
            Canonicalization::ExclusiveC14NWithComments => {
                "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
            }
            Canonicalization::InclusiveC14N => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            Canonicalization::InclusiveC14NWithComments => {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
            }
        }
    }
}

/// Signature algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// ECDSA-SHA256.
    EcdsaSha256,
    /// Ed25519.
    Ed25519,
    /// RSA-SHA256.
    RsaSha256,
}

impl SignatureAlgorithm {
    /// Algorithm identifier.
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            SignatureAlgorithm::EcdsaSha256 => {
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
            }
            SignatureAlgorithm::Ed25519 => "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
            SignatureAlgorithm::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        }
    }
}

/// A reference (something being signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    /// URI of the referenced element ("" = whole document, "#xpointer(...)" = subset).
    pub uri: String,
    /// Digest method (typically SHA-256).
    pub digest_method: String,
    /// Digest value (computed over canonicalized referenced content).
    pub digest_value: Vec<u8>,
    /// Transforms applied before digesting.
    pub transforms: Vec<Transform>,
}

/// Transform applied before digesting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    /// Exclusive C14N.
    ExclusiveC14N,
    /// Inclusive C14N.
    InclusiveC14N,
    /// Enveloped signature (strip Signature element from referenced subtree).
    EnvelopedSignature,
    /// Base64 decode.
    Base64Decode,
}

impl Transform {
    /// Algorithm identifier.
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            Transform::ExclusiveC14N => "http://www.w3.org/2001/10/xml-exc-c14n#",
            Transform::InclusiveC14N => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            Transform::EnvelopedSignature => {
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
            }
            Transform::Base64Decode => "http://www.w3.org/2000/09/xmldsig#base64",
        }
    }
}

/// SignedInfo — the part that gets signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInfo {
    /// Canonicalization algorithm.
    pub canonicalization: Canonicalization,
    /// Signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
    /// References.
    pub references: Vec<Reference>,
}

/// XMLDSig Signature structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlDSigSignature {
    /// SignedInfo (the part that gets canonicalized then signed).
    pub signed_info: SignedInfo,
    /// Signature value (over canonicalized SignedInfo).
    pub signature_value: Vec<u8>,
    /// Optional KeyInfo (cert chain, key name, etc.).
    #[serde(default)]
    pub key_info: Option<KeyInfo>,
}

/// Key information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// X509 certificate chain (DER bytes, base64-encoded in output XML).
    pub x509_certificates: Vec<String>,
    /// Optional key name.
    #[serde(default)]
    pub key_name: Option<String>,
}

/// Errors during XMLDSig operations.
#[derive(Debug, thiserror::Error)]
pub enum XmlDSigError {
    /// XML parse error.
    #[error("XML parse error: {0}")]
    XmlParse(String),
    /// Canonicalization error.
    #[error("canonicalization error: {0}")]
    Canonicalize(String),
    /// Signature verification failed.
    #[error("signature verification failed")]
    VerifyFailed,
    /// Unsupported algorithm.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Compute a SHA-256 digest over `data`. Returns the digest bytes.
pub fn sha256_digest(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Mock canonicalization: returns the input unchanged.
/// Real impl would implement RFC 3076 (Inclusive) or Exclusive C14N.
pub fn canonicalize_exclusive(xml: &str) -> Result<String, XmlDSigError> {
    Ok(xml.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_ids_correct() {
        assert_eq!(
            Canonicalization::ExclusiveC14N.algorithm_id(),
            "http://www.w3.org/2001/10/xml-exc-c14n#"
        );
        assert_eq!(
            SignatureAlgorithm::Ed25519.algorithm_id(),
            "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
        );
    }

    #[test]
    fn sha256_digest_deterministic() {
        let d1 = sha256_digest(b"hello");
        let d2 = sha256_digest(b"hello");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn mock_canonicalize_round_trips() {
        let xml = "<root>test</root>";
        let canon = canonicalize_exclusive(xml).unwrap();
        assert_eq!(canon, xml);
    }
}
