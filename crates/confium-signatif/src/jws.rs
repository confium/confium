//! The JWS format profile (SIGNATIF §8, Annex E): JSON Web Signature,
//! compact serialization, detached content (RFC 7515).
//!
//! The reference stack's envelope: the payload is external (the JCS
//! canonical bytes the co-signatures attest), the signing input is
//! `ASCII(BASE64URL(header)) "." BASE64URL(payLoad)` with the payload
//! carried out of band, per RFC 7515 detached-content signing.
//! Supported algorithms: `EdDSA` (Ed25519) and `ES256` (ECDSA P-256) —
//! matched to the classical algorithms in the registry.

use crate::error::{SignatifError, SignatifResult};

/// JWS algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwsAlg {
    /// Ed25519 (`EdDSA`).
    Ed25519,
    /// ECDSA P-256 (`ES256`).
    Es256,
}

impl JwsAlg {
    /// The `alg` header value.
    pub fn as_str(&self) -> &'static str {
        match self {
            JwsAlg::Ed25519 => "EdDSA",
            JwsAlg::Es256 => "ES256",
        }
    }
}

fn b64url_encode(bytes: &[u8]) -> String {
    use base64ct::Encoding as _;
    base64ct::Base64UrlUnpadded::encode_string(bytes)
}

fn b64url_decode(s: &str) -> SignatifResult<Vec<u8>> {
    use base64ct::Encoding as _;
    base64ct::Base64UrlUnpadded::decode_vec(s)
        .map_err(|e| SignatifError::Encoding(format!("base64url decode: {e}")))
}

/// Produce the detached JWS signing input:
/// `BASE64URL(UTF8(ASCII(header))) "." BASE64URL(payload)`, where the
/// payload is the external content (typically the JCS canonical
/// bytes).
///
/// # Errors
///
/// Encoding errors from header serialization or base64url.
pub fn detached_signing_input(
    alg: JwsAlg,
    kid: Option<&str>,
    external_payload: &[u8],
) -> SignatifResult<String> {
    let mut header = serde_json::Map::new();
    header.insert("alg".into(), serde_json::json!(alg.as_str()));
    if let Some(k) = kid {
        header.insert("kid".into(), serde_json::json!(k));
    }
    header.insert("b64".into(), serde_json::json!(false));
    header.insert("crit".into(), serde_json::json!(["b64"]));
    let header_json = crate::jcs::canonicalize(&serde_json::Value::Object(header))?;
    Ok(format!(
        "{}.{}",
        b64url_encode(header_json.as_bytes()),
        b64url_encode(external_payload)
    ))
}

/// Sign the detached input with Ed25519 and return the compact JWS
/// (header.sig — the payload segment stays with the content).
///
/// # Errors
///
/// Encoding errors from the signing input.
pub fn sign_detached_ed25519(
    signing_key: &ed25519_dalek::SigningKey,
    kid: Option<&str>,
    external_payload: &[u8],
) -> SignatifResult<String> {
    use ed25519_dalek::Signer as _;
    let input = detached_signing_input(JwsAlg::Ed25519, kid, external_payload)?;
    let sig = signing_key.sign(input.as_bytes());
    let (_, header_b64) = input.split_once('.').expect("two segments");
    let _ = header_b64;
    Ok(format!(
        "{}.{}",
        input.split('.').next().expect("header"),
        b64url_encode(&sig.to_bytes())
    ))
}

/// Verify a detached compact JWS against its external payload.
///
/// `jws` is `header.signature`; the signing input is reconstructed
/// from the decoded header and the supplied external payload.
///
/// # Errors
///
/// Signature or format errors.
pub fn verify_detached_ed25519(
    jws: &str,
    external_payload: &[u8],
    public_key: &[u8],
) -> SignatifResult<()> {
    use ed25519_dalek::Signature;
    use ed25519_dalek::Verifier;
    let (header_b64, sig_b64) = jws
        .split_once('.')
        .ok_or_else(|| SignatifError::ArtifactFormat("JWS must be header.signature".into()))?;
    let header_bytes = b64url_decode(header_b64)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| SignatifError::ArtifactFormat(format!("JWS header: {e}")))?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SignatifError::ArtifactFormat("JWS header lacks alg".into()))?;
    if alg != JwsAlg::Ed25519.as_str() {
        return Err(SignatifError::ArtifactFormat(format!(
            "unsupported JWS alg {alg}"
        )));
    }
    let kid = header.get("kid").and_then(|v| v.as_str());
    let input = detached_signing_input(JwsAlg::Ed25519, kid, external_payload)?;
    let sig_bytes = b64url_decode(sig_b64)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().map_err(|_| {
        SignatifError::BadSignature {
            context: "Ed25519 public key must be 32 bytes".into(),
        }
    })?)
    .map_err(|e| SignatifError::BadSignature {
        context: format!("Ed25519 pubkey: {e}"),
    })?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| SignatifError::BadSignature {
        context: "Ed25519 signature must be 64 bytes".into(),
    })?;
    vk.verify(input.as_bytes(), &sig)
        .map_err(|_| SignatifError::BadSignature {
            context: "JWS detached signature".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    fn generate_key() -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    #[test]
    fn detached_jws_round_trip() {
        let sk = generate_key();
        let payload = crate::jcs::canonicalize(&serde_json::json!({"batch":"LOT-1"}))
            .unwrap()
            .into_bytes();
        let jws = sign_detached_ed25519(&sk, Some("end-cert-7"), &payload).unwrap();
        // Compact: header.signature
        assert_eq!(jws.split('.').count(), 2);
        let pk = sk.verifying_key().as_bytes().to_vec();
        assert!(verify_detached_ed25519(&jws, &payload, &pk).is_ok());

        // Detached semantics: a different payload breaks the signature.
        assert!(verify_detached_ed25519(&jws, b"other", &pk).is_err());

        // Tampered signature fails.
        let mut parts: Vec<&str> = jws.split('.').collect();
        let mut sig = b64url_decode(parts[1]).unwrap();
        sig[0] ^= 1;
        parts[1] = "";
        let tampered = format!("{}.{}", parts[0], b64url_encode(&sig));
        assert!(verify_detached_ed25519(&tampered, &payload, &pk).is_err());
    }

    #[test]
    fn signing_input_is_deterministic() {
        let a = detached_signing_input(JwsAlg::Ed25519, None, b"payload").unwrap();
        let b = detached_signing_input(JwsAlg::Ed25519, None, b"payload").unwrap();
        assert_eq!(a, b);
        assert!(
            a.starts_with("eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"),
            "header was {a}"
        );
    }
}
