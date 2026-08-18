//! HTTP handlers for the verification service.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use confium_composite::{
    ComponentSignature, CompositeSignature, ECDSA_P256, ED25519, ed25519_verifier, p256_verifier,
};
use confium_signatif::graph::{SignatureVerifier, TrustGraph};
use confium_signatif::{artifact::TrustedArtifact, bundle::TrustAnchorBundle, registry::Registry};
use confium_transparency::entry::MerkleEntry;
use confium_transparency::merkle::{Hash, InclusionProof, MerkleTree, ProofStep, Side};

/// Request: verify a composite signature.
#[derive(Debug, Deserialize)]
pub struct VerifyCompositeRequest {
    /// Message bytes (hex).
    pub message_hex: String,
    /// Composite signature components.
    pub components: Vec<ComponentInput>,
}

/// One component of a composite signature.
#[derive(Debug, Deserialize)]
pub struct ComponentInput {
    /// Algorithm (e.g., "Ed25519", "ECDSA-P256").
    pub algorithm: String,
    /// Public key (hex).
    pub public_key_hex: String,
    /// Signature (hex).
    pub signature_hex: String,
}

/// Response: verification result.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub component_count: usize,
    pub errors: Vec<String>,
}

/// Request: verify an inclusion proof.
#[derive(Debug, Deserialize)]
pub struct VerifyInclusionRequest {
    /// Sequence number.
    pub sequence: u64,
    /// Leaf artifact hash (hex, 32 bytes).
    pub artifact_hash_hex: String,
    /// Root hash (hex, 32 bytes).
    pub root_hex: String,
    /// Proof steps: each is { sibling_hex, side }.
    pub steps: Vec<ProofStepInput>,
}

/// One step of an inclusion proof.
#[derive(Debug, Deserialize)]
pub struct ProofStepInput {
    /// Sibling hash (hex, 32 bytes).
    pub sibling_hex: String,
    /// Side: "left" or "right".
    pub side: String,
}

/// Shared application state.
#[derive(Clone, Default)]
pub struct AppState;

/// POST /verify/composite
pub async fn verify_composite(
    State(_state): State<AppState>,
    Json(req): Json<VerifyCompositeRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let message = hex::decode(&req.message_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid message_hex: {e}")))?;

    let mut components = Vec::new();
    for (i, c) in req.components.iter().enumerate() {
        let pk = hex::decode(&c.public_key_hex).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid public_key_hex at index {i}: {e}"),
            )
        })?;
        let sig = hex::decode(&c.signature_hex).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid signature_hex at index {i}: {e}"),
            )
        })?;
        components.push(ComponentSignature {
            algorithm: c.algorithm.clone(),
            public_key: pk,
            signature: sig,
        });
    }

    let composite = CompositeSignature::new(components);
    let result = composite
        .verify(&message, |alg, pk, m, sig| {
            if alg == ED25519 {
                ed25519_verifier(alg, pk, m, sig)
            } else if alg == ECDSA_P256 {
                p256_verifier(alg, pk, m, sig)
            } else {
                Err(format!("unsupported algorithm: {alg}"))
            }
        })
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("verify error: {e}")))?;

    let errors: Vec<String> = result
        .per_component
        .iter()
        .filter_map(|c| c.error.clone())
        .collect();

    Ok(Json(VerifyResponse {
        verified: result.all_verified,
        component_count: result.per_component.len(),
        errors,
    }))
}

/// POST /verify/inclusion
pub async fn verify_inclusion(
    State(_state): State<AppState>,
    Json(req): Json<VerifyInclusionRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let artifact_hash = decode_hash(&req.artifact_hash_hex).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid artifact_hash_hex: {e}"),
        )
    })?;
    let root = decode_hash(&req.root_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid root_hex: {e}")))?;

    let mut steps = Vec::new();
    for (i, s) in req.steps.iter().enumerate() {
        let sibling = decode_hash(&s.sibling_hex).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid sibling_hex at step {i}: {e}"),
            )
        })?;
        let side = match s.side.to_lowercase().as_str() {
            "left" => Side::Left,
            "right" => Side::Right,
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("invalid side at step {i}: {}", s.side),
                ));
            }
        };
        steps.push(ProofStep { sibling, side });
    }

    let entry = MerkleEntry::new(
        req.sequence,
        confium_transparency::entry::ArtifactType::ThresholdSignature,
        artifact_hash,
    );
    let proof = InclusionProof {
        sequence: req.sequence,
        steps,
    };

    match MerkleTree::verify_inclusion(&entry, &proof, root) {
        Ok(()) => Ok(Json(VerifyResponse {
            verified: true,
            component_count: 1,
            errors: vec![],
        })),
        Err(e) => Ok(Json(VerifyResponse {
            verified: false,
            component_count: 1,
            errors: vec![format!("{e:?}")],
        })),
    }
}

/// GET /healthz
pub async fn healthz() -> &'static str {
    "ok"
}

fn decode_hash(hex_str: &str) -> Result<Hash, String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    fn app() -> axum::Router {
        axum::Router::new()
            .route("/verify/composite", axum::routing::post(verify_composite))
            .route("/verify/signatif", axum::routing::post(verify_signatif))
            .route("/verify/inclusion", axum::routing::post(verify_inclusion))
            .route("/healthz", axum::routing::get(healthz))
            .with_state(AppState)
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn verify_composite_rejects_bad_hex() {
        let body = serde_json::json!({
            "message_hex": "not-hex!!",
            "components": []
        });
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/verify/composite")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_inclusion_rejects_bad_root() {
        let body = serde_json::json!({
            "sequence": 0,
            "artifact_hash_hex": "00",
            "root_hex": "00",
            "steps": []
        });
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/verify/inclusion")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_inclusion_accepts_valid_proof() {
        let mut tree = MerkleTree::new();
        tree.append(MerkleEntry::new(
            0,
            confium_transparency::entry::ArtifactType::ThresholdSignature,
            [1u8; 32],
        ));
        let root = tree.root();
        let proof = tree.inclusion_proof(0).unwrap();
        let entry = tree.entry(0).unwrap();

        let steps_json: Vec<_> = proof
            .steps
            .iter()
            .map(|s| {
                serde_json::json!({
                    "sibling_hex": hex::encode(s.sibling),
                    "side": match s.side {
                        Side::Left => "left",
                        Side::Right => "right",
                    }
                })
            })
            .collect();

        let body = serde_json::json!({
            "sequence": 0,
            "artifact_hash_hex": hex::encode(entry.artifact_hash),
            "root_hex": hex::encode(root),
            "steps": steps_json
        });

        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/verify/inclusion")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn decode_hash_validates_length() {
        assert!(decode_hash("00").is_err());
        assert!(decode_hash(&"ab".repeat(32)).is_ok());
    }
}

/// Request: verify a SIGNATIF trusted artifact through the full
/// pipeline. The four framework objects arrive as embedded JSON.
#[derive(Debug, Deserialize)]
pub struct VerifySignatifRequest {
    /// The trusted artifact.
    pub artifact: serde_json::Value,
    /// The trust anchor bundle.
    pub bundle: serde_json::Value,
    /// The trust graph.
    pub graph: serde_json::Value,
    /// The scheme registry; defaults to the initial values when absent.
    #[serde(default)]
    pub registry: Option<serde_json::Value>,
    /// Verification options (transparency/time inputs, accepted
    /// labels); defaults when absent.
    #[serde(default)]
    pub options: VerifySignatifOptions,
}

/// Options for the pipeline run.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct VerifySignatifOptions {
    /// Transparency inclusion was verified for this artifact.
    #[serde(default)]
    pub transparency_included: bool,
    /// An external time anchor was verified.
    #[serde(default)]
    pub time_anchored: bool,
    /// Externally-attested time (RFC 3339).
    #[serde(default)]
    pub time_attested_at: Option<String>,
    /// Multi-log quorum met.
    #[serde(default)]
    pub multi_log_quorum: bool,
    /// Accepted classification labels (empty = reject everything).
    #[serde(default)]
    pub accepted_labels: Vec<String>,
}

/// Response: the graduated verification outcome.
#[derive(Debug, Serialize)]
pub struct VerifySignatifResponse {
    /// The scheme's classification label.
    pub label: String,
    /// The verifier's acceptance decision.
    pub accept: bool,
    /// The objective coverage report.
    pub coverage: confium_signatif::coverage::CoverageReport,
}

/// The server's verifier fleet: the classical algorithms of the
/// default registry.
struct ServerVerifier;

impl SignatureVerifier for ServerVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        ed25519_verifier(ED25519, public_key, message, signature).is_ok()
            || p256_verifier(ECDSA_P256, public_key, message, signature).is_ok()
    }
}

/// POST /verify/signatif
pub async fn verify_signatif(
    State(_state): State<AppState>,
    Json(req): Json<VerifySignatifRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let respond = |status: StatusCode, body: serde_json::Value| (status, Json(body));
    let artifact: TrustedArtifact = match serde_json::from_value(req.artifact) {
        Ok(a) => a,
        Err(e) => {
            return respond(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": format!("artifact: {e}")}),
            );
        }
    };
    let bundle: TrustAnchorBundle = match serde_json::from_value(req.bundle) {
        Ok(b) => b,
        Err(e) => {
            return respond(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": format!("bundle: {e}")}),
            );
        }
    };
    let graph: TrustGraph = match serde_json::from_value(req.graph) {
        Ok(g) => g,
        Err(e) => {
            return respond(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": format!("graph: {e}")}),
            );
        }
    };
    let registry: Registry = match req.registry {
        Some(v) => match serde_json::from_value(v) {
            Ok(r) => r,
            Err(e) => {
                return respond(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": format!("registry: {e}")}),
                );
            }
        },
        None => Registry::with_initial_values(),
    };
    let time_attested_at = match &req.options.time_attested_at {
        None => None,
        Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
            Ok(t) => Some(t.with_timezone(&chrono::Utc)),
            Err(e) => {
                return respond(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": format!("time_attested_at: {e}")}),
                );
            }
        },
    };
    let no_revocations = confium_signatif::revocation::NoRevocations;
    let acceptance = confium_signatif::coverage::AcceptancePolicy {
        accepted_labels: req.options.accepted_labels,
    };
    let pipe = confium_signatif::pipeline::Pipeline::new(
        &bundle,
        &graph,
        &registry,
        &ServerVerifier,
        &no_revocations,
        confium_signatif::pipeline::TransparencyInputs {
            artifact_included: req.options.transparency_included,
            time_anchored: req.options.time_anchored,
            time_attested_at,
            multi_log_quorum: req.options.multi_log_quorum,
            downgrades: vec![],
        },
        &acceptance,
    );
    match pipe.run(&artifact, chrono::Utc::now()) {
        Ok(outcome) => {
            let accept = outcome.acceptance == confium_signatif::coverage::Acceptance::Accept;
            respond(
                StatusCode::OK,
                serde_json::to_value(VerifySignatifResponse {
                    label: outcome.label.0,
                    accept,
                    coverage: outcome.report,
                })
                .unwrap_or_default(),
            )
        }
        Err(e) => respond(
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({"error": format!("{e}"), "label": "rejected"}),
        ),
    }
}
