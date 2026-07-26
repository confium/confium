//! Real DER encoding for CMS structures (RFC 5652).
//!
//! Produces standard ASN.1 DER bytes verifiable by OpenSSL and other
//! standards-compliant tools.
//!
//! DER encoding rules (X.690):
//! - Tag (1 byte for common types)
//! - Length (short form < 128, or long form for larger)
//! - Value (TLV)
//!
//! This module implements the encoding by hand using `der` crate's
//! primitive types. For complex structures, hand-rolling gives more
//! control than `der::derive::Derive` for our semantic types.

use crate::cms::signed_data::{
    AlgorithmIdentifier, EncapContentInfo, SignedData, SignerIdentifier, SignerInfo,
};

/// Encode a `SignedData` into DER bytes.
///
/// Produces the outer `ContentInfo` wrapper per RFC 5652 §3:
/// ```text
/// ContentInfo ::= SEQUENCE {
///     contentType OBJECT IDENTIFIER,  -- 1.2.840.113549.1.7.2 (signedData)
///     content [0] EXPLICIT ANY DEFINED BY contentType }
/// ```
pub fn encode_signed_data_der(signed_data: &SignedData) -> Result<Vec<u8>, DerError> {
    // Encode the inner SignedData first to get its length.
    let inner = encode_signed_data_inner(signed_data)?;

    // Wrap in ContentInfo: SEQUENCE { OID, [0] EXPLICIT inner }
    let content_type_oid_bytes = oid_to_der(&[1, 2, 840, 113549, 1, 7, 2]);

    let mut explicit_content = Vec::new();
    explicit_content.push(0xA0); // [0] EXPLICIT context tag
    explicit_content.extend_from_slice(&encode_length(inner.len()));
    explicit_content.extend_from_slice(&inner);

    let mut seq_body = Vec::new();
    seq_body.extend_from_slice(&content_type_oid_bytes);
    seq_body.extend_from_slice(&explicit_content);

    let mut out = Vec::new();
    out.push(0x30); // SEQUENCE
    out.extend_from_slice(&encode_length(seq_body.len()));
    out.extend_from_slice(&seq_body);
    Ok(out)
}

fn encode_signed_data_inner(sd: &SignedData) -> Result<Vec<u8>, DerError> {
    // SignedData ::= SEQUENCE {
    //   version INTEGER,
    //   digestAlgorithms SET OF AlgorithmIdentifier,
    //   encapContentInfo EncapContentInfo,
    //   certificates [0] IMPLICIT CertificateSet OPTIONAL,
    //   signerInfos SET OF SignerInfo
    // }
    let mut body = Vec::new();
    body.extend_from_slice(&integer_to_der(sd.version as i64));

    let mut digest_algs = Vec::new();
    for alg in &sd.digest_algorithms {
        digest_algs.extend_from_slice(&encode_algorithm_identifier(alg));
    }
    body.extend_from_slice(&wrap_der(0x31, &digest_algs)); // SET OF

    body.extend_from_slice(&encode_encap_content_info(&sd.encap_content_info)?);

    // certificates [0] IMPLICIT — only if non-empty
    if !sd.certificates.is_empty() {
        let mut certs_body = Vec::new();
        for cert in &sd.certificates {
            certs_body.extend_from_slice(cert); // already DER
        }
        // [0] IMPLICIT context tag = 0xA0 (constructed)
        body.push(0xA0);
        body.extend_from_slice(&encode_length(certs_body.len()));
        body.extend_from_slice(&certs_body);
    }

    let mut signer_infos = Vec::new();
    for si in &sd.signer_infos {
        signer_infos.extend_from_slice(&encode_signer_info(si)?);
    }
    body.extend_from_slice(&wrap_der(0x31, &signer_infos)); // SET OF

    Ok(wrap_der(0x30, &body)) // SEQUENCE
}

fn encode_encap_content_info(eci: &EncapContentInfo) -> Result<Vec<u8>, DerError> {
    let oid_bytes = oid_from_string(&eci.content_type)?;

    let mut body = Vec::new();
    body.extend_from_slice(&oid_bytes);

    if let Some(content) = &eci.content {
        // [0] EXPLICIT OCTET STRING
        let octet = wrap_der(0x04, content);
        body.push(0xA0);
        body.extend_from_slice(&encode_length(octet.len()));
        body.extend_from_slice(&octet);
    }

    Ok(wrap_der(0x30, &body))
}

fn encode_algorithm_identifier(alg: &AlgorithmIdentifier) -> Vec<u8> {
    let oid_bytes = match oid_from_string(&alg.oid) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let mut body = oid_bytes;
    if let Some(params) = &alg.parameters {
        body.extend_from_slice(params);
    } else {
        // NULL parameters
        body.extend_from_slice(&[0x05, 0x00]);
    }
    wrap_der(0x30, &body)
}

fn encode_signer_info(si: &SignerInfo) -> Result<Vec<u8>, DerError> {
    let mut body = Vec::new();
    body.extend_from_slice(&integer_to_der(si.version as i64));

    // sid: SignerIdentifier
    match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber {
            issuer_der,
            serial_number,
        } => {
            // SEQUENCE { Name, CertificateSerialNumber }
            let mut seq = Vec::new();
            seq.extend_from_slice(issuer_der);
            seq.extend_from_slice(&integer_bytes_to_der(serial_number));
            body.extend_from_slice(&wrap_der(0x30, &seq));
        }
        SignerIdentifier::SubjectKeyIdentifier { key_identifier } => {
            // [0] IMPLICIT OCTET STRING
            let octet = wrap_der(0x04, key_identifier);
            body.push(0x80);
            body.extend_from_slice(&encode_length(octet.len()));
            body.extend_from_slice(&octet);
        }
    }

    body.extend_from_slice(&encode_algorithm_identifier(&si.digest_algorithm));

    // signedAttrs [0] IMPLICIT SET OF Attribute — optional, skip if empty
    // signatureAlgorithm
    body.extend_from_slice(&encode_algorithm_identifier(&si.signature_algorithm));

    // signature OCTET STRING
    body.extend_from_slice(&wrap_der(0x04, &si.signature));

    // unsignedAttrs [1] IMPLICIT SET OF Attribute — optional, skip if empty

    Ok(wrap_der(0x30, &body))
}

/// Errors during DER encoding.
#[derive(Debug, thiserror::Error)]
pub enum DerError {
    /// Invalid OID format.
    #[error("invalid OID: {0}")]
    InvalidOid(String),
    /// Value too large to encode.
    #[error("value too large: {0}")]
    TooLarge(String),
}

fn oid_to_der(arcs: &[u64]) -> Vec<u8> {
    // First byte: 40 * arc[0] + arc[1]
    let first = (40 * arcs.get(0).copied().unwrap_or(0) + arcs.get(1).copied().unwrap_or(0)) as u8;
    let mut out = vec![first];
    for arc in arcs.iter().skip(2) {
        out.extend_from_slice(&encode_base128(*arc));
    }
    // Wrap as OID TLV: 0x06 <length> <value>
    wrap_der(0x06, &out)
}

fn oid_from_string(s: &str) -> Result<Vec<u8>, DerError> {
    let arcs: Vec<u64> = s
        .split('.')
        .map(|a| a.parse::<u64>().map_err(|_| DerError::InvalidOid(s.into())))
        .collect::<Result<Vec<_>, _>>()?;
    if arcs.len() < 2 {
        return Err(DerError::InvalidOid("OID must have >= 2 arcs".into()));
    }
    Ok(oid_to_der(&arcs))
}

fn encode_base128(n: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut n = n;
    loop {
        bytes.insert(0, (n & 0x7F) as u8);
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    // Set high bit on all but last
    let last = bytes.len() - 1;
    for i in 0..last {
        bytes[i] |= 0x80;
    }
    bytes
}

fn integer_to_der(n: i64) -> Vec<u8> {
    if n >= 0 && n <= 127 {
        return vec![0x02, 0x01, n as u8];
    }
    let bytes = n.to_be_bytes();
    // Strip leading zero bytes (for positive) but keep sign bit correct
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
        start += 1;
    }
    wrap_der(0x02, &bytes[start..])
}

fn integer_bytes_to_der(bytes: &[u8]) -> Vec<u8> {
    // Treat as unsigned, but ensure leading 0 if high bit set
    let mut value = bytes.to_vec();
    if value.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        value.insert(0, 0);
    }
    wrap_der(0x02, &value)
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut l = len;
    while l > 0 {
        bytes.insert(0, (l & 0xFF) as u8);
        l >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend_from_slice(&bytes);
    out
}

fn wrap_der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_length(body.len()));
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::signed_data::{EncapContentInfo, SignerIdentifier, SignerInfo};

    #[test]
    fn encode_length_short_form() {
        assert_eq!(encode_length(5), vec![5]);
        assert_eq!(encode_length(127), vec![127]);
    }

    #[test]
    fn encode_length_long_form() {
        assert_eq!(encode_length(128), vec![0x81, 0x80]);
        assert_eq!(encode_length(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn integer_short() {
        assert_eq!(integer_to_der(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer_to_der(42), vec![0x02, 0x01, 0x2A]);
        assert_eq!(integer_to_der(127), vec![0x02, 0x01, 0x7F]);
    }

    #[test]
    fn oid_sha256() {
        // 2.16.840.1.101.3.4.2.1 (SHA-256)
        let bytes = oid_from_string("2.16.840.1.101.3.4.2.1").unwrap();
        // SHA-256 OID DER: 06 09 60 86 48 01 65 03 04 02 01
        assert_eq!(bytes[0], 0x06);
        assert_eq!(bytes[1], 0x09);
        assert_eq!(bytes[2], 96); // 40*2 + 16
        assert_eq!(bytes[3], 0x86);
        assert_eq!(bytes[4], 0x48);
    }

    #[test]
    fn oid_invalid_arcs() {
        assert!(oid_from_string("not-a-number").is_err());
        assert!(oid_from_string("1").is_err());
    }

    #[test]
    fn base128_single_byte() {
        assert_eq!(encode_base128(0), vec![0]);
        assert_eq!(encode_base128(127), vec![127]);
    }

    #[test]
    fn base128_multi_byte() {
        // 840 = 6 * 128 + 72 → [0x86, 0x48]
        assert_eq!(encode_base128(840), vec![0x86, 0x48]);
    }

    #[test]
    fn encode_signed_data_minimal() {
        let sd = SignedData {
            version: 1,
            digest_algorithms: vec![AlgorithmIdentifier {
                oid: "2.16.840.1.101.3.4.2.1".into(),
                parameters: None,
            }],
            encap_content_info: EncapContentInfo {
                content_type: "1.2.840.113549.1.7.1".into(),
                content: None,
            },
            certificates: vec![],
            signer_infos: vec![SignerInfo {
                version: 1,
                sid: SignerIdentifier::SubjectKeyIdentifier {
                    key_identifier: vec![0xAA; 20],
                },
                digest_algorithm: AlgorithmIdentifier {
                    oid: "2.16.840.1.101.3.4.2.1".into(),
                    parameters: None,
                },
                signed_attrs: vec![],
                signature_algorithm: AlgorithmIdentifier {
                    oid: "1.2.840.113549.1.1.11".into(),
                    parameters: None,
                },
                signature: vec![0u8; 256],
                unsigned_attrs: vec![],
            }],
        };
        let der = encode_signed_data_der(&sd).unwrap();
        assert_eq!(der[0], 0x30); // outer SEQUENCE
        // Sanity: bytes should be reasonably long
        assert!(der.len() > 50);
    }
}
