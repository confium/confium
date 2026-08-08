//! Certificate parsing for the log server.
//!
//! Wraps `confium_pki::cert::Certificate` to extract the metadata
//! the cert-aware API endpoints need: issuer DN, subject DN,
//! validity window, SHA-256 fingerprint.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertMetadata {
    pub fingerprint_sha256: String,
    pub issuer_distinguished_name: String,
    pub subject_distinguished_name: String,
    pub valid_from: String,
    pub valid_to: String,
    pub serial_hex: String,
}

/// Parse a DER-encoded X.509 certificate and extract the metadata
/// the log server stores alongside the leaf hash. The leaf hash is
/// SHA-256 of the DER bytes (the certificate fingerprint).
pub fn parse_der(der_bytes: &[u8]) -> Result<CertMetadata> {
    let cert =
        confium_pki::cert::Certificate::from_der(der_bytes).context("parsing DER certificate")?;
    let issuer = cert.as_inner().tbs_certificate.issuer.to_string();
    let subject = cert.as_inner().tbs_certificate.subject.to_string();
    Ok(CertMetadata {
        fingerprint_sha256: cert.fingerprint_sha256(),
        issuer_distinguished_name: issuer,
        subject_distinguished_name: subject,
        valid_from: cert.not_before_chrono().to_rfc3339(),
        valid_to: cert.not_after_chrono().to_rfc3339(),
        serial_hex: hex::encode(cert.serial_bytes()),
    })
}

/// Compute the SHA-256 fingerprint of a byte slice. Used as the
/// leaf hash for cert entries.
pub fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest: [u8; 32] = h.finalize().into();
    digest
}

/// Classify a certificate into one of the Confium "artifact types"
/// based on the Extended Key Usage extension (if present). CNML
/// certificates, code-signing certs, document-signing certs, TLS
/// server certs, etc. each get a distinct type label.
pub fn classify_cert(_der_bytes: &[u8], meta: &CertMetadata) -> String {
    // The full implementation would inspect the EKU extension. For
    // the scaffold, we classify by subject DN pattern matching:
    let subj = meta.subject_distinguished_name.to_lowercase();
    if subj.contains("cnml") || subj.contains("certificate of conformity") {
        "cnml_certificate".to_string()
    } else if subj.contains("code sign") || subj.contains("codesign") {
        "code_signing_certificate".to_string()
    } else if subj.contains("email") || subj.contains("smime") {
        "email_signing_certificate".to_string()
    } else if subj.contains("document") {
        "document_signing_certificate".to_string()
    } else if subj.contains("tsa") || subj.contains("timestamping") {
        "timestamping_certificate".to_string()
    } else {
        "x509_certificate".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_cnml_cert_by_subject_dn() {
        let meta = CertMetadata {
            fingerprint_sha256: "00".repeat(32),
            issuer_distinguished_name: "CNML Root CA".to_string(),
            subject_distinguished_name: "Acme CNML Cert".to_string(),
            valid_from: "2026-01-01T00:00:00Z".to_string(),
            valid_to: "2027-01-01T00:00:00Z".to_string(),
            serial_hex: "00".to_string(),
        };
        assert_eq!(classify_cert(&[], &meta), "cnml_certificate");
    }

    #[test]
    fn fingerprint_is_32_bytes() {
        let fp = fingerprint(b"hello");
        assert_eq!(fp.len(), 32);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        assert_eq!(fingerprint(b"hello"), fingerprint(b"hello"));
    }
}
