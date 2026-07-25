//! CMS verification.

use crate::envelope::CmsError;
use crate::signed_data::SignedData;

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
}

/// Verify a SignedData structure. The `verifier` callback receives
/// (signer_index, public_key_der, signed_data_to_verify, signature_bytes)
/// and returns Ok(()) if valid.
///
/// For real-world use, the verifier typically uses a crypto library
/// (openssl, ring, rustls) to verify the signature.
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
        // Find the signer's certificate (very simplified: by key ID match)
        let cert_der = signed_data
            .certificates
            .first()
            .cloned()
            .unwrap_or_default();

        // Extract the public key from the cert (would use confium-cert in real impl)
        let pubkey = cert_der.as_slice();

        // Build the data that was signed: typically signed_attrs re-encoded.
        // For this skeleton: payload bytes (real impl would canonicalize attrs).
        let signed_bytes = if signed_data.encap_content_info.content.is_some() {
            signed_data.encap_content_info.content.clone().unwrap_or_default()
        } else {
            payload.to_vec()
        };

        match verifier(i, pubkey, &signed_bytes, &signer.signature) {
            Ok(()) => per_signer.push(SignerVerification {
                signer_index: i,
                verified: true,
                error: None,
            }),
            Err(e) => {
                all_verified = false;
                per_signer.push(SignerVerification {
                    signer_index: i,
                    verified: false,
                    error: Some(e),
                });
            }
        }
    }

    Ok(VerificationResult {
        all_verified,
        per_signer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::build_detached_signature;

    #[test]
    fn verify_with_accepting_callback_passes() {
        let sd = build_detached_signature(
            vec![0u8; 32],
            "1.2.840.113549.1.1.11",
            vec![0u8; 256],
            vec![vec![0u8; 100]],
        )
        .unwrap();
        let result = verify_signed_data(&sd, b"hello", |_, _, _, _| Ok(())).unwrap();
        assert!(result.all_verified);
        assert_eq!(result.per_signer.len(), 1);
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
        assert_eq!(result.per_signer[0].error.as_deref(), Some("bad"));
    }
}
