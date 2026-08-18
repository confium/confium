//! EU Digital Product Passport composition with SIGNATIF (Annex H).
//!
//! Pattern 1 — **DPP record as SIGNATIF payload**: the DPP JSON record
//! is the canonical payload of a trusted artifact; the manufacturer's
//! data-dimension attestation plus a person attestation (the
//! responsible engineer) converge on it, and the artifact climbs the
//! classification ladder. The registry pattern (Annex H.3 — the DPP
//! registry as a multi-operator transparency log) is demonstrated via
//! the M-of-K multi-log policy.

use chrono::Utc;
use ed25519_dalek::Signer;
use rand_core::RngCore;

use confium_signatif::artifact::{ArtifactVersion, TrustedArtifact};
use confium_signatif::bundle::{AnchorRoot, TrustAnchorBundle};
use confium_signatif::coverage::HardCheckStatus;
use confium_signatif::graph::{
    AuthorityKind, AuthorityNode, DelegationEdge, SignatureVerifier, TrustGraph,
};
use confium_signatif::multilog::{LogInclusion, MultiLogAttestation, MultiLogPolicy};
use confium_signatif::pipeline::{Pipeline, TransparencyInputs};
use confium_signatif::registry::DimensionTag;
use confium_signatif::registry::Registry;
use confium_signatif::revocation::NoRevocations;
use confium_signatif::scope::ScopeDimensions;

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
    let registry = Registry::with_initial_values();

    // Topology: EU market-surveillance root -> manufacturer -> line key.
    let root_sk = generate_key();
    let mfr_sk = generate_key();
    let line_sk = generate_key();
    let engineer_sk = generate_key();

    let root = AuthorityNode {
        id: "eu-ms-root".into(),
        kind: AuthorityKind::Root,
        public_key: root_sk.verifying_key().as_bytes().to_vec(),
        quorum: None,
        scope: ScopeDimensions::unconstrained(),
    };
    let mfr = AuthorityNode {
        id: "mfr-acme".into(),
        kind: AuthorityKind::Delegated,
        public_key: mfr_sk.verifying_key().as_bytes().to_vec(),
        quorum: None,
        scope: ScopeDimensions::unconstrained(),
    };
    let line = AuthorityNode {
        id: "line-key-3".into(),
        kind: AuthorityKind::EndCertificate,
        public_key: line_sk.verifying_key().as_bytes().to_vec(),
        quorum: None,
        scope: ScopeDimensions::unconstrained(),
    };

    let mut graph = TrustGraph::new();
    graph.add_node(root.clone());
    graph.add_node(mfr.clone());
    graph.add_node(line.clone());
    graph
        .add_delegation(DelegationEdge {
            parent: "eu-ms-root".into(),
            child: "mfr-acme".into(),
            signature: root_sk
                .sign(&mfr.binding_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        })
        .unwrap();
    graph
        .add_delegation(DelegationEdge {
            parent: "mfr-acme".into(),
            child: "line-key-3".into(),
            signature: mfr_sk
                .sign(&line.binding_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        })
        .unwrap();

    let mut bundle = TrustAnchorBundle {
        bundle_version: "2026.08".into(),
        valid_from: Utc::now() - chrono::Duration::hours(1),
        valid_until: Utc::now() + chrono::Duration::days(365),
        roots: vec![AnchorRoot {
            name: "eu-ms-root".into(),
            aggregate_key: root.public_key.clone(),
            fingerprint: hex::encode(&root.public_key),
            quorum: None,
        }],
        transparency_logs: vec![],
        bundle_signature: vec![],
        update_log: None,
    };
    let msg = bundle.signing_bytes().unwrap();
    bundle.bundle_signature = root_sk.sign(&msg).to_bytes().to_vec();

    // Pattern 1: the DPP record IS the SIGNATIF payload.
    let dpp_record = serde_json::json!({
        "dppId": "dpp-acme-battery-000042",
        "product": "rechargeable-battery-pack",
        "manufacturer": "ACME Energy",
        "carbonFootprint": {"value": 41.2, "unit": "kgCO2e", "scope": "cradle-to-gate"},
        "recycledContent": {"value": 18, "unit": "percent"},
        "substancesOfConcern": [],
        "repairabilityScore": 7.8,
        "conformity": {"ce": true, "declarationRef": "DoC-2026-118"},
    });
    let mut dpp = TrustedArtifact::new(
        ArtifactVersion { major: 1, minor: 0 },
        "dpp-acme-battery-000042",
        dpp_record,
        Some("https://ec.europa.eu/dpp/schema/battery-v1.json".into()),
    )
    .unwrap();

    // Manufacturer data attestation (line key signs the record).
    dpp.sign(
        DimensionTag::data(),
        "Ed25519",
        "line-key-3",
        line_sk.verifying_key().as_bytes().to_vec(),
        "eu-ms-root",
        &|m| line_sk.sign(m).to_bytes().to_vec(),
        &registry,
    )
    .unwrap();

    // Pattern 1 continued: the responsible engineer's person
    // attestation rides on the same DPP record.
    dpp.sign(
        DimensionTag::person(),
        "Ed25519",
        "line-key-3",
        engineer_sk.verifying_key().as_bytes().to_vec(),
        "eu-ms-root",
        &|m| engineer_sk.sign(m).to_bytes().to_vec(),
        &registry,
    )
    .unwrap();

    // Pattern 3: the DPP registry as multi-operator transparency —
    // the inclusion quorum is 2 of 3 independent registry operators.
    let policy = MultiLogPolicy { m: 2, k: 3 };
    let attestation = MultiLogAttestation {
        inclusions: vec![
            LogInclusion {
                log: "eu-dpp-primary".into(),
                included: true,
            },
            LogInclusion {
                log: "member-state-mirror".into(),
                included: true,
            },
            LogInclusion {
                log: "ngo-watchdog".into(),
                included: false,
            },
        ],
    };
    let multi_log_quorum = attestation.satisfies(&policy).unwrap();
    assert!(multi_log_quorum, "2 of 3 operators included the DPP");

    let no_revocations = NoRevocations;
    let acceptance = confium_signatif::coverage::AcceptancePolicy::accept(&[
        "verified",
        "attested",
        "certified",
    ]);
    let pipe = Pipeline::new(
        &bundle,
        &graph,
        &registry,
        &Ed25519Verifier,
        &no_revocations,
        TransparencyInputs {
            artifact_included: true,
            time_anchored: true,
            time_attested_at: Some(Utc::now()),
            multi_log_quorum,
            downgrades: vec![],
        },
        &acceptance,
    );
    let out = pipe.run(&dpp, Utc::now()).expect("pipeline");
    assert_eq!(out.report.hard_checks, HardCheckStatus::Pass);
    assert_eq!(out.report.dimensions_verified, vec!["data", "person"]);
    println!("DPP classification: {}", out.label.0);
    println!(
        "coverage: transparency={} time={} multilog={} roots={}",
        out.report.transparency_included,
        out.report.time_anchored,
        out.report.multi_log_quorum,
        out.report.independent_roots
    );
    println!(
        "pattern 2 (data carrier) is the inverse binding: the DPP QR/carrier references the artifact id {} and verifies through the same anchor bundle",
        dpp.artifact_id
    );
    println!("\nDPP composed with SIGNATIF through Confium: OK");
}
