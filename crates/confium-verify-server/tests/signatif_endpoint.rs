//! POST /verify/signatif — the full SIGNATIF pipeline over HTTP.

use tower::ServiceExt;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::Signer;
use rand_core::RngCore;

use confium_signatif::artifact::TrustedArtifact;
use confium_signatif::bundle::TrustAnchorBundle;
use confium_signatif::graph::{AuthorityKind, AuthorityNode, DelegationEdge, TrustGraph};
use confium_signatif::registry::{DimensionTag, Registry};

fn generate_key() -> ed25519_dalek::SigningKey {
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn fixture() -> serde_json::Value {
    let registry = Registry::with_initial_values();
    let root_sk = generate_key();
    let end_sk = generate_key();
    let root = AuthorityNode {
        id: "root".into(),
        kind: AuthorityKind::Root,
        public_key: root_sk.verifying_key().as_bytes().to_vec(),
        quorum: None,
        scope: confium_signatif::scope::ScopeDimensions::unconstrained(),
    };
    let end = AuthorityNode {
        id: "end".into(),
        kind: AuthorityKind::EndCertificate,
        public_key: end_sk.verifying_key().as_bytes().to_vec(),
        quorum: None,
        scope: confium_signatif::scope::ScopeDimensions::unconstrained(),
    };
    let mut graph = TrustGraph::new();
    graph.add_node(root.clone());
    graph.add_node(end.clone());
    graph
        .add_delegation(DelegationEdge {
            parent: "root".into(),
            child: "end".into(),
            signature: root_sk
                .sign(&end.binding_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        })
        .unwrap();
    let mut bundle = TrustAnchorBundle {
        bundle_version: "1".into(),
        valid_from: chrono::Utc::now() - chrono::Duration::hours(1),
        valid_until: chrono::Utc::now() + chrono::Duration::days(30),
        roots: vec![confium_signatif::bundle::AnchorRoot {
            name: "root".into(),
            aggregate_key: root.public_key.clone(),
            fingerprint: hex::encode(&root.public_key),
            quorum: None,
        }],
        transparency_logs: vec![],
        update_log: None,
        bundle_signature: vec![],
    };
    let msg = bundle.signing_bytes().unwrap();
    bundle.bundle_signature = root_sk.sign(&msg).to_bytes().to_vec();
    let mut artifact = TrustedArtifact::new(
        confium_signatif::artifact::ArtifactVersion { major: 1, minor: 0 },
        "http-1",
        serde_json::json!({"dose": 500}),
        None,
    )
    .unwrap();
    artifact
        .sign(
            DimensionTag::data(),
            "Ed25519",
            "end",
            end_sk.verifying_key().as_bytes().to_vec(),
            "root",
            &|m| end_sk.sign(m).to_bytes().to_vec(),
            &registry,
        )
        .unwrap();
    serde_json::json!({
        "artifact": artifact,
        "bundle": bundle,
        "graph": graph,
        "options": {
            "transparency_included": true,
            "time_anchored": true,
            "time_attested_at": chrono::Utc::now().to_rfc3339(),
            "accepted_labels": ["basic", "verified"],
        },
    })
}

#[tokio::test]
async fn verifies_artifact_and_returns_graduated_outcome() {
    let app = confium_verify_server::router();
    let body = serde_json::to_string(&fixture()).unwrap();
    let response = app
        .oneshot(
            Request::post("/verify/signatif")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["label"], "verified");
    assert_eq!(out["accept"], true);
    assert_eq!(out["coverage"]["dimensions_verified"][0], "data");
}

#[tokio::test]
async fn tampered_artifact_is_rejected_with_422() {
    let app = confium_verify_server::router();
    let mut body = fixture();
    body["artifact"]["payload"]["dose"] = serde_json::json!(999);
    let response = app
        .oneshot(
            Request::post("/verify/signatif")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["label"], "rejected");
}
