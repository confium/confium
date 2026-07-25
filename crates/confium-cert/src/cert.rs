//! X.509 v3 certificate wrapper types.
//!
//! Wraps `x509_cert::Certificate` to provide idiomatic Rust access plus
//! Confium-specific helpers (DER/PEM, fingerprint).

use crate::result::{PathFailure, VerificationResult};
use chrono::{DateTime, Utc};
use data_encoding::HEXLOWER;
use der::Decode;
use sha2::{Digest, Sha256};

/// A parsed X.509 v3 certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    inner: x509_cert::Certificate,
    raw_der: Vec<u8>,
}

/// PKCS#10 certificate signing request (DER wrapper).
#[derive(Debug, Clone)]
pub struct CertificateSigningRequest {
    raw_der: Vec<u8>,
}

/// Errors encountered parsing or serializing certificates.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// DER decoding error.
    #[error("DER decode error: {0}")]
    Der(#[from] der::Error),

    /// PEM parsing error.
    #[error("PEM parse error: {0}")]
    Pem(String),

    /// Invalid structure.
    #[error("invalid certificate structure: {0}")]
    Invalid(String),
}

impl Certificate {
    /// Parse a certificate from DER bytes.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, CertError> {
        let inner = x509_cert::Certificate::from_der(der_bytes)?;
        Ok(Self {
            inner,
            raw_der: der_bytes.to_vec(),
        })
    }

    /// Parse a certificate from PEM (RFC 7468) text.
    pub fn from_pem(pem: &str) -> Result<Self, CertError> {
        let der = pem_to_der(pem, "CERTIFICATE")?;
        Self::from_der(&der)
    }

    /// Serialize this certificate to DER bytes.
    pub fn to_der(&self) -> Vec<u8> {
        self.raw_der.clone()
    }

    /// Serialize this certificate to PEM (RFC 7468).
    pub fn to_pem(&self) -> String {
        der_to_pem(&self.raw_der, "CERTIFICATE")
    }

    /// Compute the SHA-256 fingerprint of this certificate.
    pub fn fingerprint_sha256(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.raw_der);
        HEXLOWER.encode(&hasher.finalize())
    }

    /// The serial number as a byte slice.
    pub fn serial_bytes(&self) -> &[u8] {
        self.inner.tbs_certificate.serial_number.as_bytes()
    }

    /// Not-before validity bound (raw `der::DateTime`).
    pub fn not_before(&self) -> der::DateTime {
        self.inner.tbs_certificate.validity.not_before.to_date_time()
    }

    /// Not-after validity bound (raw `der::DateTime`).
    pub fn not_after(&self) -> der::DateTime {
        self.inner.tbs_certificate.validity.not_after.to_date_time()
    }

    /// Not-before as a chrono `DateTime<Utc>`.
    pub fn not_before_chrono(&self) -> DateTime<Utc> {
        chrono::DateTime::from(self.not_before().to_system_time())
    }

    /// Not-after as a chrono `DateTime<Utc>`.
    pub fn not_after_chrono(&self) -> DateTime<Utc> {
        chrono::DateTime::from(self.not_after().to_system_time())
    }

    /// Whether the certificate is within its validity window at the given instant.
    pub fn is_within_validity(&self, now: DateTime<Utc>) -> bool {
        let nb = self.not_before_chrono();
        let na = self.not_after_chrono();
        now >= nb && now <= na
    }

    /// Raw subject public key bytes from the SPKI, if available.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.inner
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap_or(&[])
    }

    /// Reference to the underlying `x509_cert` type.
    pub fn as_inner(&self) -> &x509_cert::Certificate {
        &self.inner
    }
}

impl CertificateSigningRequest {
    /// Parse a CSR from DER bytes. Performs only a basic structural check
    /// (top-level SEQUENCE); full field parsing is the application's job.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, CertError> {
        if der_bytes.is_empty() {
            return Err(CertError::Invalid("CSR bytes empty".into()));
        }
        // Tag 0x30 = SEQUENCE, the expected first byte of any CSR.
        if der_bytes[0] != 0x30 {
            return Err(CertError::Invalid(format!(
                "CSR expected to start with SEQUENCE tag 0x30, got {:#x}",
                der_bytes[0]
            )));
        }
        Ok(Self {
            raw_der: der_bytes.to_vec(),
        })
    }

    /// Parse a CSR from PEM text.
    pub fn from_pem(pem: &str) -> Result<Self, CertError> {
        let der = pem_to_der(pem, "CERTIFICATE REQUEST")?;
        Self::from_der(&der)
    }

    /// Serialize to DER bytes.
    pub fn to_der(&self) -> Vec<u8> {
        self.raw_der.clone()
    }

    /// Serialize to PEM text.
    pub fn to_pem(&self) -> String {
        der_to_pem(&self.raw_der, "CERTIFICATE REQUEST")
    }
}

/// Quick helper for path validation — checks time validity of the leaf only.
pub fn quick_check_leaf_validity(cert: &Certificate, now: DateTime<Utc>) -> VerificationResult {
    let mut checks = Vec::new();
    let mut valid = true;

    let nb = cert.not_before_chrono();
    let na = cert.not_after_chrono();

    if now < nb {
        checks.push(PathFailure::NotYetValid);
        valid = false;
    }
    if now > na {
        checks.push(PathFailure::Expired);
        valid = false;
    }

    VerificationResult { valid, checks }
}

fn pem_to_der(pem: &str, expected_label: &str) -> Result<Vec<u8>, CertError> {
    let trimmed = pem.trim();
    let header = format!("-----BEGIN {expected_label}-----");
    let footer = format!("-----END {expected_label}-----");

    let start = trimmed
        .find(&header)
        .ok_or_else(|| CertError::Pem(format!("missing {header}")))?
        + header.len();
    let end = trimmed
        .find(&footer)
        .ok_or_else(|| CertError::Pem(format!("missing {footer}")))?;

    let body: String = trimmed[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    data_encoding::BASE64
        .decode(body.as_bytes())
        .map_err(|e| CertError::Pem(format!("base64 decode failed: {e}")))
}

fn der_to_pem(der: &[u8], label: &str) -> String {
    let encoded = data_encoding::BASE64.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_der_round_trip_synthetic() {
        let der = vec![1u8, 2, 3, 4, 5];
        let pem = der_to_pem(&der, "TEST");
        assert!(pem.contains("-----BEGIN TEST-----"));
        assert!(pem.contains("-----END TEST-----"));
        let recovered = pem_to_der(&pem, "TEST").expect("parse");
        assert_eq!(recovered, der);
    }

    #[test]
    fn pem_to_der_rejects_missing_header() {
        let result = pem_to_der("no headers here", "CERTIFICATE");
        assert!(result.is_err());
    }

    #[test]
    fn pem_to_der_rejects_missing_footer() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n"; // base64("abc")
        let result = pem_to_der(pem, "CERTIFICATE");
        assert!(result.is_err());
    }

    #[test]
    fn csr_rejects_non_sequence_first_byte() {
        let result = CertificateSigningRequest::from_der(&[0x01, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn csr_accepts_sequence_first_byte() {
        let csr = CertificateSigningRequest::from_der(&[0x30, 0x00]);
        assert!(csr.is_ok());
    }
}
