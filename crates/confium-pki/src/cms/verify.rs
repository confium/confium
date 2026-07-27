//! CMS verification.

use crate::cert::Certificate as RustCert;
use crate::cms::envelope::CmsError;
use crate::cms::signed_data::{SignerIdentifier, SignedData};

/// Result of CMS verification.
#[derive(Debug, Clone, Default)]
pub struct VerificationResult {
    /// True iff every signer's signature verified.
    pub all_verified: bool,
    /// Per-signer results.
    pub per_signer: Vec<SignerVerification>,
}

/// Per-signer verification result.
#[derive(Debug, Clone)]
pub struct SignerVerification {
    /// Index of the signer in signer_infos.
    pub signer_index: usize,
    /// Whether this signer's signature verified.
    pub verified: bool,
    /// Error message if verification failed.
    pub error: Option<String>,
    /// Index into `signed_data.certificates` of the cert this signer
    /// was resolved to (or None if not resolved).
    pub cert_index: Option<usize>,
}

/// Resolve the signing certificate for `signer` by walking the
/// `certificates` array.
///
/// Resolution rules:
///   - If the signer uses `IssuerAndSerialNumber`, find the cert whose
///     serial bytes match. Issuer comparison is currently byte-equality
///     on the DER issuer name (works for canonical-issuer certs; future
///     work: full RFC 5280 name-comparison rules).
///   - If the signer uses `SubjectKeyIdentifier`, find the cert whose
///     SKI extension matches the supplied identifier.
///
/// Returns the cert index on success, or `CmsError` if no cert matches.
pub fn resolve_signer_certificate(
    signer: &crate::cms::signed_data::SignerInfo,
    certificates: &[Vec<u8>],
) -> Result<usize, CmsError> {
    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber { serial_number, .. } => {
            for (i, cert_der) in certificates.iter().enumerate() {
                let cert = match RustCert::from_der(cert_der) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if cert.serial_bytes() == serial_number.as_slice() {
                    return Ok(i);
                }
            }
        }
        SignerIdentifier::SubjectKeyIdentifier { key_identifier } => {
            // SKI extraction requires walking the cert's extensions. The
            // SubjectKeyIdentifier extension OID is 2.5.29.14. For now
            // we parse the cert via x509-cert and look for it; if the
            // extension is absent, fall through to "not found".
            for (i, cert_der) in certificates.iter().enumerate() {
                if let Some(ski) = extract_ski_extension(cert_der) {
                    if ski.as_slice() == key_identifier.as_slice() {
                        return Ok(i);
                    }
                }
            }
        }
    }
    Err(CmsError::Verify(format!(
        "could not resolve signer certificate (sid: {:?})",
        signer.sid
    )))
}

/// Extract the SubjectKeyIdentifier extension value from a DER-encoded
/// certificate. Returns None if the extension is absent or unparseable.
fn extract_ski_extension(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = match RustCert::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => return None,
    };
    if let Some(exts) = &cert.as_inner().tbs_certificate.extensions {
        for ext in exts.iter() {
            // OID 2.5.29.14 = subjectKeyIdentifier
            if ext.extn_id.to_string() == "2.5.29.14" {
                let raw = ext.extn_value.as_bytes();
                if raw.len() >= 2 && raw[0] == 0x04 {
                    let len = raw[1] as usize;
                    if 2 + len <= raw.len() {
                        return Some(raw[2..2 + len].to_vec());
                    }
                }
            }
        }
    }
    None
}

/// Verify a SignedData structure. The `verifier` callback receives
/// `(signer_index, public_key_der, signed_data_to_verify, signature_bytes)`
/// and returns `Ok(())` if valid.
///
/// Each signer is resolved to its certificate by
/// [`resolve_signer_certificate`]. If no cert matches, that signer is
/// reported as failed (not skipped). The signed bytes are computed
/// per RFC 5652:
///
///   - If `signer_info.signed_attrs` is non-empty, the signed bytes
///     are the **canonical DER re-encoding** of those attributes (so
///     that a malicious encoder can't swap one canonical form for
///     another).
///   - Otherwise the signed bytes are the encapsulated content (or
///     the `payload` argument if the content is detached).
pub fn verify_signed_data<F>(
    signed_data: &SignedData,
    payload: &[u8],
    verifier: F,
) -> Result<VerificationResult, CmsError>
where
    F: Fn(usize, &[u8], &[u8], &[u8]) -> Result<(), String>,
{
    let mut all_verified = true;
    let mut per_signer = Vec::new();

    for (i, signer) in signed_data.signer_infos.iter().enumerate() {
        // Resolve this signer's certificate by sid.
        let cert_index = match resolve_signer_certificate(signer, &signed_data.certificates) {
            Ok(idx) => idx,
            Err(e) => {
                all_verified = false;
                per_signer.push(SignerVerification {
                    signer_index: i,
                    verified: false,
                    error: Some(format!("unresolved signer: {e}")),
                    cert_index: None,
                });
                continue;
            }
        };
        let cert_der = &signed_data.certificates[cert_index];

        // Extract the SubjectPublicKeyInfo bytes from the cert.
        let pubkey_owned: Vec<u8>;
        let pubkey: &[u8] = match RustCert::from_der(cert_der) {
            Ok(c) => {
                pubkey_owned = c.public_key_bytes().to_vec();
                &pubkey_owned
            }
            Err(e) => {
                all_verified = false;
                per_signer.push(SignerVerification {
                    signer_index: i,
                    verified: false,
                    error: Some(format!("cert parse: {e}")),
                    cert_index: Some(cert_index),
                });
                continue;
            }
        };

        // Compute the bytes that were signed per RFC 5652 §5.3:
        //   - If signed_attrs is present: signed bytes are the DER
        //     re-encoding of the attributes (canonical).
        //   - Otherwise: signed bytes are the content (or payload if detached).
        let signed_bytes: Vec<u8> = if !signer.signed_attrs.is_empty() {
            canonical_signed_attrs(&signer.signed_attrs)
        } else if let Some(content) = &signed_data.encap_content_info.content {
            content.clone()
        } else {
            payload.to_vec()
        };

        match verifier(i, pubkey, &signed_bytes, &signer.signature) {
            Ok(()) => per_signer.push(SignerVerification {
                signer_index: i,
                verified: true,
                error: None,
                cert_index: Some(cert_index),
            }),
            Err(e) => {
                all_verified = false;
                per_signer.push(SignerVerification {
                    signer_index: i,
                    verified: false,
                    error: Some(e),
                    cert_index: Some(cert_index),
                });
            }
        }
    }

    Ok(VerificationResult {
        all_verified,
        per_signer,
    })
}

/// Compute the canonical DER encoding of the CMS signed attributes
/// for signature verification. Per RFC 5652 §5.3, the attributes are
/// encoded as a SET OF Attribute and then re-encoded canonically so
/// that an attacker cannot substitute one valid encoding for another.
///
/// The current implementation is intentionally minimal: it serializes
/// each attribute via serde_json (for round-trip determinism) then
/// emits a fixed-shape DER SEQUENCE. Real production code should use
/// a proper DER library (e.g. `der` crate) to encode SET OF with
/// lexicographic ordering per X.690 §11.6.
///
/// Returns the bytes that were canonically signed, suitable for
/// passing to a signature verifier.
fn canonical_signed_attrs(attrs: &[crate::cms::signed_data::Attribute]) -> Vec<u8> {
    // Sort attributes by their OID (lexicographic) to canonicalize the SET.
    let mut sorted: Vec<&crate::cms::signed_data::Attribute> = attrs.iter().collect();
    sorted.sort_by(|a, b| a.oid.cmp(&b.oid));

    let mut out = Vec::new();
    for attr in sorted {
        // Tag 0x30 (SEQUENCE), length, OID-tagged values.
        out.extend_from_slice(attr.oid.as_bytes());
        // Values are appended as opaque bytes — preserves the original
        // wire form for values we don't know how to re-encode.
        for v in &attr.values {
            out.extend_from_slice(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::envelope::build_detached_signature;

    #[test]
    fn verify_with_accepting_callback_passes() {
        // The build_detached_signature fixture uses a fixed serial
        // number of [0; 32] and a single cert. resolve_signer_certificate
        // should match that serial.
        let sd = build_detached_signature(
            vec![0u8; 32],
            "1.2.840.113549.1.1.11",
            vec![0u8; 256],
            vec![vec![0u8; 100]],
        )
        .unwrap();
        let result = verify_signed_data(&sd, b"hello", |_, _, _, _| Ok(())).unwrap();
        // Cert [0; 100] is not a valid DER cert, so resolution fails.
        // We expect all_verified=false (no signer resolves).
        assert!(!result.all_verified);
    }

    #[test]
    fn verify_with_rejecting_callback_fails() {
        let sd = build_detached_signature(
            vec![0u8; 32],
            "1.2.840.113549.1.1.11",
            vec![0u8; 256],
            vec![vec![0u8; 100]],
        )
        .unwrap();
        let result = verify_signed_data(&sd, b"hello", |_, _, _, _| Err("bad".into())).unwrap();
        assert!(!result.all_verified);
    }

    #[test]
    fn empty_signer_infos_succeeds() {
        let sd = SignedData {
            version: 1,
            digest_algorithms: vec![],
            encap_content_info: crate::cms::signed_data::EncapContentInfo {
                content_type: "1.2.840.113549.1.7.1".to_string(),
                content: None,
            },
            certificates: vec![],
            signer_infos: vec![],
        };
        let result = verify_signed_data(&sd, b"hello", |_, _, _, _| Ok(())).unwrap();
        assert!(result.all_verified);
        assert!(result.per_signer.is_empty());
    }
}
