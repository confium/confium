//! Browser/Node.js verification of SIGNATIF trusted artifacts.
//!
//! A thin transport adapter: JSON in, JSON out. The verification
//! assembly (fleet, revocation view, transparency inputs, acceptance)
//! lives in [`confium_signatif::verify`]; this binding pins the
//! browser verifier profile (Ed25519-only) and translates types.

use wasm_bindgen::prelude::*;

use confium_signatif::artifact::TrustedArtifact;
use confium_signatif::bundle::TrustAnchorBundle;
use confium_signatif::graph::TrustGraph;
use confium_signatif::registry::Registry;
use confium_signatif::verify::{Fleet, VerifyOptions};

/// The full verification outcome as one JSON object: `coverage` (the
/// objective report), `label` (the scheme's classification), and
/// `accept` (the verifier's acceptance decision).
///
/// # Errors
///
/// Returns a human-readable error string for malformed JSON inputs,
/// deserialization failures, or a hard-check failure (the pipeline
/// short-circuits; the error names the failing check).
#[wasm_bindgen(js_name = verifyTrustedArtifact)]
pub fn verify_trusted_artifact(
    artifact_json: &str,
    bundle_json: &str,
    graph_json: &str,
    registry_json: &str,
    options_json: &str,
) -> Result<String, JsError> {
    let artifact: TrustedArtifact =
        serde_json::from_str(artifact_json).map_err(|e| JsError::new(&format!("artifact: {e}")))?;
    let bundle: TrustAnchorBundle =
        serde_json::from_str(bundle_json).map_err(|e| JsError::new(&format!("bundle: {e}")))?;
    let graph: TrustGraph =
        serde_json::from_str(graph_json).map_err(|e| JsError::new(&format!("graph: {e}")))?;
    let registry: Registry =
        serde_json::from_str(registry_json).map_err(|e| JsError::new(&format!("registry: {e}")))?;

    let mut options: VerifyOptions = if options_json.trim().is_empty() {
        VerifyOptions::default()
    } else {
        serde_json::from_str(options_json).map_err(|e| JsError::new(&format!("options: {e}")))?
    };
    // The browser verifier profile is Ed25519-only by design.
    options.fleet = Fleet::Ed25519;

    let verdict = confium_signatif::verify::verify_trusted_artifact(
        &artifact, &bundle, &graph, &registry, &options,
    )
    .map_err(|e| JsError::new(&format!("{e}")))?;
    serde_json::to_string(&verdict).map_err(|e| JsError::new(&format!("encode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn fixture() -> (String, String, String, String) {
        use ed25519_dalek::Signer;
        use rand_core::RngCore;

        fn generate_key() -> ed25519_dalek::SigningKey {
            let mut seed = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut seed);
            ed25519_dalek::SigningKey::from_bytes(&seed)
        }

        let registry = Registry::with_initial_values();
        let root_sk = generate_key();
        let end_sk = generate_key();
        let root = confium_signatif::graph::AuthorityNode {
            id: "root".into(),
            kind: confium_signatif::graph::AuthorityKind::Root,
            public_key: root_sk.verifying_key().as_bytes().to_vec(),
            quorum: None,
            scope: confium_signatif::scope::ScopeDimensions::unconstrained(),
        };
        let end = confium_signatif::graph::AuthorityNode {
            id: "end".into(),
            kind: confium_signatif::graph::AuthorityKind::EndCertificate,
            public_key: end_sk.verifying_key().as_bytes().to_vec(),
            quorum: None,
            scope: confium_signatif::scope::ScopeDimensions::unconstrained(),
        };
        let mut graph = TrustGraph::new();
        graph.add_node(root.clone());
        graph.add_node(end.clone());
        use confium_signatif::graph::DelegationEdge;
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
            "wasm-1",
            serde_json::json!({"dose": 500}),
            None,
        )
        .unwrap();
        artifact
            .sign(
                confium_signatif::registry::DimensionTag::data(),
                "Ed25519",
                "end",
                end_sk.verifying_key().as_bytes().to_vec(),
                "root",
                &|m| end_sk.sign(m).to_bytes().to_vec(),
                &registry,
            )
            .unwrap();

        (
            serde_json::to_string(&artifact).unwrap(),
            serde_json::to_string(&bundle).unwrap(),
            serde_json::to_string(&graph).unwrap(),
            serde_json::to_string(&registry).unwrap(),
        )
    }

    #[wasm_bindgen_test]
    fn verifies_and_ladders_in_the_browser() {
        let (a, b, g, r) = fixture();
        let options = serde_json::json!({
            "transparency_included": false,
            "time_anchored": false,
            "accepted_labels": ["unverified", "basic", "verified"],
        })
        .to_string();
        let out: serde_json::Value =
            serde_json::from_str(&verify_trusted_artifact(&a, &b, &g, &r, &options).unwrap())
                .unwrap();
        assert_eq!(out["label"], "unverified");
        assert_eq!(out["accept"], true);

        let options = serde_json::json!({
            "transparency_included": true,
            "time_anchored": true,
            "time_attested_at": chrono::Utc::now().to_rfc3339(),
            "accepted_labels": ["verified"],
        })
        .to_string();
        let out: serde_json::Value =
            serde_json::from_str(&verify_trusted_artifact(&a, &b, &g, &r, &options).unwrap())
                .unwrap();
        assert_eq!(out["label"], "verified");
        assert_eq!(out["accept"], true);
        assert_eq!(out["coverage"]["paths_found"], 1);
    }

    #[wasm_bindgen_test]
    fn tampered_artifact_hard_fails() {
        let (a, b, g, r) = fixture();
        let mut artifact: serde_json::Value = serde_json::from_str(&a).unwrap();
        artifact["payload"]["dose"] = serde_json::json!(999);
        let err = verify_trusted_artifact(
            &artifact.to_string(),
            &b,
            &g,
            &r,
            r#"{"accepted_labels":["verified"]}"#,
        )
        .unwrap_err();
        assert!(
            format!("{err:?}").contains("signature_validity"),
            "got {err:?}"
        );
    }
}
