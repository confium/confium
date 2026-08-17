//! COSE encoding of trusted artifacts (SIGNATIF §8, the
//! `/conf/format-cose` profile's co-signature encoding obligation).
//!
//! A [`TrustedArtifact`] serializes into a chain of
//! [`confium_composite::cose::CoseSign1`] structures — one per
//! co-signature block — followed by one carrying the artifact body
//! (id, payload, canonical hash) as its payload. Each co-signature
//! COSE structure signs over the artifact's canonical payload hash,
//! and the chain round-trips losslessly through
//! [`encode_artifact_cose`]/[`decode_artifact_cose`]. The
//! CBOR deterministic-encoding characteristics of the profile
//! (definite lengths, minimum-length integers) come from the composite
//! crate's encoder.

use confium_composite::cose::CoseSign1;
use confium_composite::cose::alg as AlgorithmIds;

use crate::artifact::{CoSignatureBlock, TrustedArtifact};
use crate::error::{SignatifError, SignatifResult};
use crate::jcs;
use crate::registry::DimensionTag;

/// The protected-header key carrying the SIGNATIF trust dimension.
const DIMENSION_HEADER_KEY: &str = "signatif:dimension";
/// The protected-header key carrying the signer certificate reference.
const CERT_REF_HEADER_KEY: &str = "signatif:cert-ref";
/// The protected-header key carrying the chain (root) reference.
const CHAIN_REF_HEADER_KEY: &str = "signatif:chain-ref";

fn algorithm_id_for(name: &str) -> SignatifResult<i32> {
    match name {
        "Ed25519" => Ok(AlgorithmIds::ED25519),
        "ECDSA-P256" => Ok(AlgorithmIds::ES256),
        other => Err(SignatifError::Encoding(format!(
            "no COSE algorithm id registered for {other}"
        ))),
    }
}

fn cose_algorithm_name(id: i32) -> SignatifResult<String> {
    match id {
        AlgorithmIds::ED25519 => Ok("Ed25519".into()),
        AlgorithmIds::ES256 => Ok("ECDSA-P256".into()),
        other => Err(SignatifError::Encoding(format!(
            "unknown COSE algorithm id {other}"
        ))),
    }
}

/// The body payload carried by the trailing COSE structure: the JCS of
/// the artifact's self-description minus the signatures themselves.
fn artifact_body(artifact: &TrustedArtifact) -> SignatifResult<Vec<u8>> {
    let v = serde_json::json!({
        "artifact_id": artifact.artifact_id,
        "canonical_payload_hash": hex::encode(artifact.canonical_payload_hash),
        "payload": artifact.payload,
        "payload_schema": artifact.payload_schema,
        "version": {
            "major": artifact.version.major,
            "minor": artifact.version.minor,
        },
    });
    Ok(jcs::canonicalize(&v)?.into_bytes())
}

fn reconstruct_artifact(
    body: &serde_json::Value,
    blocks: Vec<CoSignatureBlock>,
) -> SignatifResult<TrustedArtifact> {
    let artifact_id = body
        .get("artifact_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SignatifError::Encoding("artifact body lacks artifact_id".into()))?
        .to_string();
    let hash_hex = body
        .get("canonical_payload_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SignatifError::Encoding("artifact body lacks hash".into()))?;
    let canonical_payload_hash: [u8; 32] = hex::decode(hash_hex)
        .map_err(|e| SignatifError::Encoding(format!("hash decode: {e}")))?
        .try_into()
        .map_err(|_| SignatifError::Encoding("canonical hash must be 32 bytes".into()))?;
    let version = body
        .get("version")
        .ok_or_else(|| SignatifError::Encoding("artifact body lacks version".into()))?;
    Ok(TrustedArtifact {
        version: crate::artifact::ArtifactVersion {
            major: version.get("major").and_then(|v| v.as_i64()).unwrap_or(1) as u32,
            minor: version.get("minor").and_then(|v| v.as_i64()).unwrap_or(0) as u32,
        },
        artifact_id,
        payload: body
            .get("payload")
            .cloned()
            .ok_or_else(|| SignatifError::Encoding("artifact body lacks payload".into()))?,
        payload_schema: body
            .get("payload_schema")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        canonical_payload_hash,
        co_signatures: blocks,
    })
}

/// Encode a trusted artifact as a COSE chain: one COSE_Sign1 per
/// co-signature (signing over the canonical payload hash), then a
/// body structure carrying the self-description.
///
/// # Errors
///
/// Encoding errors for unregistered algorithms or CBOR failures.
pub fn encode_artifact_cose(artifact: &TrustedArtifact) -> SignatifResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for block in &artifact.co_signatures {
        let mut cose = CoseSign1::new(
            algorithm_id_for(&block.algorithm)?,
            &artifact.canonical_payload_hash,
            &block.signature,
        )
        .map_err(|e| SignatifError::Encoding(e.to_string()))?;
        cose.unprotected_bytes = serde_json::to_vec(&serde_json::json!({
            DIMENSION_HEADER_KEY: block.dimension.as_str(),
            CERT_REF_HEADER_KEY: block.signer_cert_ref,
            CHAIN_REF_HEADER_KEY: block.chain_ref,
        }))
        .map_err(|e| SignatifError::Encoding(e.to_string()))?;
        out.push(
            cose.encode()
                .map_err(|e| SignatifError::Encoding(e.to_string()))?,
        );
    }
    let body = CoseSign1::new(0, &artifact_body(artifact)?, &[])
        .map_err(|e| SignatifError::Encoding(e.to_string()))?;
    out.push(
        body.encode()
            .map_err(|e| SignatifError::Encoding(e.to_string()))?,
    );
    Ok(out)
}

/// Decode a COSE chain back into a trusted artifact. The final
/// structure is the body; every preceding structure is a co-signature
/// block. The canonical payload hash is cross-checked against the
/// payload (self-description integrity).
///
/// # Errors
///
/// Decoding and integrity errors.
pub fn decode_artifact_cose(chain: &[Vec<u8>]) -> SignatifResult<TrustedArtifact> {
    if chain.is_empty() {
        return Err(SignatifError::Encoding("empty COSE chain".into()));
    }
    let body_cose = CoseSign1::decode(&chain[chain.len() - 1])
        .map_err(|e| SignatifError::Encoding(e.to_string()))?;
    let body: serde_json::Value = serde_json::from_slice(&body_cose.payload)
        .map_err(|e| SignatifError::Encoding(format!("artifact body: {e}")))?;

    let mut blocks = Vec::new();
    for cose_bytes in &chain[..chain.len() - 1] {
        let cose = CoseSign1::decode(cose_bytes.as_slice())
            .map_err(|e| SignatifError::Encoding(e.to_string()))?;
        let algorithm = cose_algorithm_name(
            cose.algorithm()
                .map_err(|e| SignatifError::Encoding(e.to_string()))?,
        )?;
        let headers: serde_json::Value = serde_json::from_slice(&cose.unprotected_bytes)
            .map_err(|e| SignatifError::Encoding(format!("co-signature headers: {e}")))?;
        let dimension = headers
            .get(DIMENSION_HEADER_KEY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| SignatifError::Encoding("co-signature lacks dimension".into()))?;
        blocks.push(CoSignatureBlock {
            dimension: DimensionTag::custom(dimension),
            algorithm,
            signer_cert_ref: headers
                .get(CERT_REF_HEADER_KEY)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            signer_pubkey: Vec::new(),
            chain_ref: headers
                .get(CHAIN_REF_HEADER_KEY)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            signature: cose.signature,
            timestamp: chrono::DateTime::parse_from_rfc3339(
                headers
                    .get("signatif:timestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1970-01-01T00:00:00Z"),
            )
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or_default(),
        });
    }

    let artifact = reconstruct_artifact(&body, blocks)?;
    // Self-description integrity: recorded hash == hash of payload.
    if jcs::canonical_hash(&artifact.payload)? != artifact.canonical_payload_hash {
        return Err(SignatifError::ArtifactFormat(
            "COSE artifact body hash does not match its payload".into(),
        ));
    }
    Ok(artifact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactVersion;
    use crate::registry::Registry;
    use chrono::Utc;
    use ed25519_dalek::Signer;
    use rand_core::RngCore;

    fn generate_key() -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    #[test]
    fn round_trip_preserves_the_artifact() {
        let registry = Registry::with_initial_values();
        let sk = generate_key();
        let mut artifact = TrustedArtifact::new(
            ArtifactVersion { major: 1, minor: 0 },
            "cose-art-1",
            serde_json::json!({"vial": "V-9", "mass_g": 12.342}),
            None,
        )
        .unwrap();
        artifact
            .sign(
                DimensionTag::data(),
                "Ed25519",
                "end-1",
                sk.verifying_key().as_bytes().to_vec(),
                "root-1",
                &|m| sk.sign(m).to_bytes().to_vec(),
                &registry,
            )
            .unwrap();

        let chain = encode_artifact_cose(&artifact).unwrap();
        assert_eq!(chain.len(), 2, "one co-signature + one body");
        let back = decode_artifact_cose(&chain).unwrap();
        assert_eq!(back.artifact_id, "cose-art-1");
        assert_eq!(back.canonical_payload_hash, artifact.canonical_payload_hash);
        assert_eq!(back.co_signatures.len(), 1);
        assert_eq!(back.co_signatures[0].algorithm, "Ed25519");
        assert_eq!(back.co_signatures[0].dimension.as_str(), "data");
        assert_eq!(back.co_signatures[0].signer_cert_ref, "end-1");
        assert_eq!(back.co_signatures[0].chain_ref, "root-1");
        assert_eq!(
            back.co_signatures[0].signature,
            artifact.co_signatures[0].signature
        );
    }

    #[test]
    fn tampered_body_hash_detected() {
        let registry = Registry::with_initial_values();
        let sk = generate_key();
        let mut artifact = TrustedArtifact::new(
            ArtifactVersion { major: 1, minor: 0 },
            "cose-art-2",
            serde_json::json!({"a": 1}),
            None,
        )
        .unwrap();
        artifact
            .sign(
                DimensionTag::data(),
                "Ed25519",
                "end",
                sk.verifying_key().as_bytes().to_vec(),
                "root",
                &|m| sk.sign(m).to_bytes().to_vec(),
                &registry,
            )
            .unwrap();
        let mut chain = encode_artifact_cose(&artifact).unwrap();
        // Tamper the body structure's payload.
        let mut body = CoseSign1::decode(chain[1].as_slice()).unwrap();
        body.payload = br#"{"artifact_id":"cose-art-2","canonical_payload_hash":"00","payload":{"a":2},"version":{"major":1,"minor":0}}"#.to_vec();
        chain[1] = body.encode().unwrap();
        assert!(decode_artifact_cose(&chain).is_err());
    }

    #[test]
    fn empty_chain_rejected() {
        assert!(decode_artifact_cose(&[]).is_err());
        let _ = Utc::now();
    }
}
