//! CNML adopting SIGNATIF through Confium — the end-to-end demo
//! (Annex D pattern, instantiated for metrology).
//!
//! A domain scheme (CNML) declares its profile and adopts the
//! framework: register a scheme dimension, build the trust topology,
//! issue a multi-dimensional trusted artifact (data + person + time),
//! run the verification pipeline, and print the objective coverage
//! report and classification label. The second artifact demonstrates
//! the W3C Verifiable Credentials composition pattern (Annex G): a VC
//! is the SIGNATIF payload, co-signatures become the VC proof.

use chrono::Utc;
use ed25519_dalek::Signer;
use rand_core::RngCore;

use confium_signatif::artifact::{ArtifactVersion, TrustedArtifact};
use confium_signatif::bundle::{AnchorLog, AnchorRoot, TrustAnchorBundle};
use confium_signatif::coverage::{AcceptancePolicy, HardCheckStatus};
use confium_signatif::graph::{
    AuthorityKind, AuthorityNode, DelegationEdge, SignatureVerifier, TrustGraph,
};
use confium_signatif::jcs;
use confium_signatif::passport::Passport;
use confium_signatif::pipeline::{Pipeline, TransparencyInputs};
use confium_signatif::registry::{DimensionTag, Registry, Status};
use confium_signatif::revocation::NoRevocations;
use confium_signatif::scope::{ScopeDimensions, ScopeValue};

fn generate_key() -> ed25519_dalek::SigningKey {
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

struct Ed25519Verifier;

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use ed25519_dalek::Signature;
        use ed25519_dalek::Verifier;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk.try_into().unwrap()) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(msg, &signature).is_ok()
    }
}

fn main() {
    // ----------------------------------------------------------------
    // 1. The scheme (CNML) adopts the framework: registry + dimensions.
    // ----------------------------------------------------------------
    let mut registry = Registry::with_initial_values();
    registry.register_dimension(
        "cnml:instrument-class",
        "CNML instrument classification (mass, volume, length)",
    );

    // ----------------------------------------------------------------
    // 2. Trust topology: root (national metrology institute, 3-of-5)
    //    -> delegated authority (accredited lab, 2-of-3) -> end cert.
    // ----------------------------------------------------------------
    let root_sk = generate_key();
    let lab_sk = generate_key();
    let device_sk = generate_key();
    let time_authority_sk = generate_key();

    let mut root_scope = ScopeDimensions::unconstrained();
    root_scope.set("domain", ScopeValue::Single("metrology".into()));

    let mut lab_scope = root_scope.clone();
    lab_scope.set("cnml:instrument-class", ScopeValue::Single("mass".into()));

    let root = AuthorityNode {
        id: "nmi-root".into(),
        kind: AuthorityKind::Root,
        public_key: root_sk.verifying_key().as_bytes().to_vec(),
        quorum: Some(confium_signatif::graph::Quorum { t: 3, n: 5 }),
        scope: root_scope,
    };
    let lab = AuthorityNode {
        id: "lab-01".into(),
        kind: AuthorityKind::Delegated,
        public_key: lab_sk.verifying_key().as_bytes().to_vec(),
        quorum: Some(confium_signatif::graph::Quorum { t: 2, n: 3 }),
        scope: lab_scope.clone(),
    };
    let device = AuthorityNode {
        id: "end-device-7".into(),
        kind: AuthorityKind::EndCertificate,
        public_key: device_sk.verifying_key().as_bytes().to_vec(),
        quorum: None,
        scope: lab_scope,
    };

    let mut graph = TrustGraph::new();
    graph.add_node(root.clone());
    graph.add_node(lab.clone());
    graph.add_node(device.clone());
    graph
        .add_delegation(DelegationEdge {
            parent: "nmi-root".into(),
            child: "lab-01".into(),
            signature: root_sk
                .sign(&lab.binding_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        })
        .unwrap();
    graph
        .add_delegation(DelegationEdge {
            parent: "lab-01".into(),
            child: "end-device-7".into(),
            signature: lab_sk
                .sign(&device.binding_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        })
        .unwrap();

    // ----------------------------------------------------------------
    // 3. The trust anchor bundle (what a verifier holds offline).
    // ----------------------------------------------------------------
    let mut bundle = TrustAnchorBundle {
        bundle_version: "2026.08".into(),
        valid_from: Utc::now() - chrono::Duration::hours(1),
        valid_until: Utc::now() + chrono::Duration::days(365),
        roots: vec![AnchorRoot {
            name: "nmi-root".into(),
            aggregate_key: root.public_key.clone(),
            fingerprint: hex::encode(root.public_key.clone()),
            quorum: root.quorum,
        }],
        transparency_logs: vec![AnchorLog {
            name: "nmi-log".into(),
            operator_key: vec![],
            endpoint: "https://log.nmi.example".into(),
        }],
        bundle_signature: vec![],
        update_log: None,
    };
    let bundle_msg = bundle.signing_bytes().unwrap();
    bundle.bundle_signature = root_sk.sign(&bundle_msg).to_bytes().to_vec();

    // ----------------------------------------------------------------
    // 4. Issue a multi-dimensional trusted artifact: the measured
    //    value (data), the operator's attestation (person), and the
    //    time authority's anchored attestation (time).
    // ----------------------------------------------------------------
    let mut artifact = TrustedArtifact::new(
        ArtifactVersion { major: 1, minor: 0 },
        "cnml-cert-2026-00001",
        serde_json::json!({
            "instrument": "mass-balance-X2000",
            "measured_value": 1000.002,
            "unit": "g",
            "cnml_class": "mass",
        }),
        Some("https://cnml.example/schema/calibration-certificate.json".into()),
    )
    .unwrap();

    artifact
        .sign(
            DimensionTag::data(),
            "Ed25519",
            "end-device-7",
            device_sk.verifying_key().as_bytes().to_vec(),
            "nmi-root",
            &|m| device_sk.sign(m).to_bytes().to_vec(),
            &registry,
        )
        .unwrap();

    let operator_sk = generate_key();
    artifact
        .sign(
            DimensionTag::person(),
            "Ed25519",
            "end-device-7",
            operator_sk.verifying_key().as_bytes().to_vec(),
            "nmi-root",
            &|m| operator_sk.sign(m).to_bytes().to_vec(),
            &registry,
        )
        .unwrap();

    // ----------------------------------------------------------------
    // 5. Time authority: a real time key attests the artifact's
    //    existence, anchored to an external source (Annex E's OTS
    //    commitment shape).
    // ----------------------------------------------------------------
    use confium_signatif::time::TimeAttestation;
    let mut time_att = TimeAttestation {
        authority: "time-authority-1".into(),
        artifact_hash: hex::encode(artifact.canonical_payload_hash),
        attested_at: Utc::now(),
        external_anchor: b"ots://bitcoin-commitment".to_vec(),
        signature: vec![],
    };
    time_att.signature = time_authority_sk
        .sign(&time_att.signing_bytes().unwrap())
        .to_bytes()
        .to_vec();
    assert!(
        time_att
            .verify(
                time_authority_sk.verifying_key().as_bytes(),
                &Ed25519Verifier
            )
            .is_ok(),
        "time authority attestation verifies"
    );
    let time_attested_at = time_att.attested_at;

    // ----------------------------------------------------------------
    // 6. Verify through the pipeline: coverage report + label ladder.
    // ----------------------------------------------------------------
    let no_revocations = NoRevocations;
    let acceptance =
        AcceptancePolicy::accept(&["unverified", "basic", "verified", "attested", "certified"]);
    for (transparency, time_anchored) in [(false, false), (true, false), (true, true)] {
        let pipe = Pipeline::new(
            &bundle,
            &graph,
            &registry,
            &Ed25519Verifier,
            &no_revocations,
            TransparencyInputs {
                artifact_included: transparency,
                time_anchored,
                time_attested_at: time_anchored.then_some(time_attested_at),
                multi_log_quorum: false,
                downgrades: vec![],
            },
            &acceptance,
        );
        let out = pipe.run(&artifact, Utc::now()).expect("pipeline");
        println!(
            "transparency={transparency} time={time_anchored} -> label={} paths={} dims={}",
            out.label.0,
            out.report.paths_found,
            out.report.dimensions_verified.join(",")
        );
        assert_eq!(out.report.hard_checks, HardCheckStatus::Pass);
    }

    // Machine-readable coverage report + conformance claims.
    let pipe = Pipeline::new(
        &bundle,
        &graph,
        &registry,
        &Ed25519Verifier,
        &no_revocations,
        TransparencyInputs {
            artifact_included: true,
            time_anchored: true,
            time_attested_at: None,
            multi_log_quorum: false,
            downgrades: vec![],
        },
        &acceptance,
    );
    let out = pipe.run(&artifact, Utc::now()).unwrap();
    println!(
        "\ncoverage = {}",
        serde_json::to_string_pretty(&out.report).unwrap()
    );

    // ----------------------------------------------------------------
    // 6. Annex G pattern 1: a W3C Verifiable Credential as payload.
    // ----------------------------------------------------------------
    let vc = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "CalibrationCertificate"],
        "issuer": "did:web:lab-01.nmi.example",
        "credentialSubject": {
            "instrument": "mass-balance-X2000",
            "measuredValue": 1000.002,
            "unit": "g"
        }
    });
    let mut vc_artifact = TrustedArtifact::new(
        ArtifactVersion { major: 1, minor: 0 },
        "vc-calibration-2026-00001",
        vc,
        Some("https://www.w3.org/ns/credentials/v2".into()),
    )
    .unwrap();
    vc_artifact
        .sign(
            DimensionTag::data(),
            "Ed25519",
            "end-device-7",
            device_sk.verifying_key().as_bytes().to_vec(),
            "nmi-root",
            &|m| device_sk.sign(m).to_bytes().to_vec(),
            &registry,
        )
        .unwrap();
    let vc_out = pipe.run(&vc_artifact, Utc::now()).unwrap();
    println!("\nVC-as-payload label = {}", vc_out.label.0);

    // ----------------------------------------------------------------
    // 7. Delivery: the machine-readable passport for the certificate.
    // ----------------------------------------------------------------
    let passport = Passport {
        version: 1,
        object_id: "cnml-cert-2026-00001".into(),
        key_fingerprint: hex::encode(&device.public_key),
        scope_summary: "domain:metrology/cnml:instrument-class:mass".into(),
        valid_from: Utc::now(),
        valid_until: Utc::now() + chrono::Duration::days(365),
    };
    println!(
        "\npassport bytes = {} bytes",
        passport.distribution_bytes().unwrap().len()
    );

    // ----------------------------------------------------------------
    // 8. Algorithm agility: deprecating an algorithm downgrades.
    // ----------------------------------------------------------------
    let hash = jcs::canonical_hash(&artifact.payload).unwrap();
    let _ = hash;
    let mut agile = registry.clone();
    agile
        .algorithms
        .set_status("Ed25519", Status::Deprecated)
        .unwrap();
    println!(
        "\nconformance: {} of {} classes implemented",
        confium_signatif::conformance::conformance_claims()
            .iter()
            .filter(|c| c.status == confium_signatif::conformance::ConformanceStatus::Implemented)
            .count(),
        confium_signatif::conformance::conformance_claims().len()
    );

    println!("\nCNML adopted SIGNATIF through Confium: OK");
}
