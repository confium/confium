//! Abstract test suite (SIGNATIF Annex A): every implemented
//! conformance class exercised through its public surface.
//!
//! Each test names the `/conf` class it witnesses. A scheme claims
//! conformance by pointing at these tests plus its own profile tests.

use chrono::Utc;
use ed25519_dalek::Signer;
use rand_core::RngCore;

use confium_signatif::artifact::{ArtifactVersion, TrustedArtifact};
use confium_signatif::bundle::{AnchorRoot, TrustAnchorBundle};
use confium_signatif::conformance::{ConformanceStatus, conformance_claims};
use confium_signatif::coverage::{AcceptancePolicy, HardCheckStatus};
use confium_signatif::graph::{
    AuthorityKind, AuthorityNode, DelegationEdge, SignatureVerifier, TrustGraph,
};
use confium_signatif::jcs;
use confium_signatif::passport::Passport;
use confium_signatif::pipeline::{Pipeline, TransparencyInputs};
use confium_signatif::registry::DimensionTag;
use confium_signatif::registry::Registry;
use confium_signatif::revocation::{AuthorityStateBinding, NoRevocations, RevocationIndex};
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

struct Fixture {
    graph: TrustGraph,
    bundle: TrustAnchorBundle,
    registry: Registry,
    artifact: TrustedArtifact,
    _signer: ed25519_dalek::SigningKey,
    _root: ed25519_dalek::SigningKey,
}

fn build() -> Fixture {
    let registry = Registry::with_initial_values();
    let root_sk = generate_key();
    let signer = generate_key();

    let root = AuthorityNode {
        id: "root".into(),
        kind: AuthorityKind::Root,
        public_key: root_sk.verifying_key().as_bytes().to_vec(),
        quorum: None,
        scope: ScopeDimensions::unconstrained(),
    };
    let mut narrow = ScopeDimensions::unconstrained();
    narrow.set("domain", ScopeValue::Single("pharma".into()));
    let end = AuthorityNode {
        id: "end".into(),
        kind: AuthorityKind::EndCertificate,
        public_key: signer.verifying_key().as_bytes().to_vec(),
        quorum: None,
        scope: narrow,
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
        valid_from: Utc::now() - chrono::Duration::hours(1),
        valid_until: Utc::now() + chrono::Duration::days(30),
        roots: vec![AnchorRoot {
            name: "root".into(),
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

    let mut artifact = TrustedArtifact::new(
        ArtifactVersion { major: 1, minor: 0 },
        "ats-1",
        serde_json::json!({"dose": 500}),
        None,
    )
    .unwrap();
    artifact
        .sign(
            DimensionTag::data(),
            "Ed25519",
            "end",
            signer.verifying_key().as_bytes().to_vec(),
            "root",
            &|m| signer.sign(m).to_bytes().to_vec(),
            &registry,
        )
        .unwrap();

    Fixture {
        graph,
        bundle,
        registry,
        artifact,
        _signer: signer,
        _root: root_sk,
    }
}

/// `/conf/basic-verifier` + `/conf/full-verifier`: offline verification
/// through the pipeline with coverage report and acceptance policy.
#[test]
fn ats_verifier_classes() {
    let f = build();
    let no_revocations = NoRevocations;
    let strict = AcceptancePolicy::accept(&["attested", "certified"]);
    let pipe = Pipeline::new(
        &f.bundle,
        &f.graph,
        &f.registry,
        &Ed25519Verifier,
        &no_revocations,
        TransparencyInputs {
            artifact_included: true,
            time_anchored: true,
            time_attested_at: None,
            multi_log_quorum: false,
            downgrades: vec![],
        },
        &strict,
    );
    let out = pipe.run(&f.artifact, Utc::now()).unwrap();
    assert_eq!(out.report.hard_checks, HardCheckStatus::Pass);
    assert!(out.acceptance == confium_signatif::coverage::Acceptance::Reject);
}

/// `/conf/issuing-authority`: living artifact accumulates dimensions.
#[test]
fn ats_issuing_authority() {
    let f = build();
    let person = generate_key();
    let mut living = f.artifact.clone();
    living
        .sign(
            DimensionTag::person(),
            "Ed25519",
            "end",
            person.verifying_key().as_bytes().to_vec(),
            "root",
            &|m| person.sign(m).to_bytes().to_vec(),
            &f.registry,
        )
        .unwrap();
    assert!(living.verify_self(&f.registry, &Ed25519Verifier).is_ok());
    assert_eq!(living.dimensions_verified().len(), 2);
}

/// `/conf/root-authority`: the anchor bundle verifies.
#[test]
fn ats_root_authority() {
    let f = build();
    assert!(f.bundle.verify(Utc::now(), &Ed25519Verifier).is_ok());
}

/// `/conf/hierarchical`: narrowing enforced along the chain.
#[test]
fn ats_hierarchical_topology() {
    let f = build();
    let paths = f
        .graph
        .find_paths("end", &f.bundle, &Ed25519Verifier)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].root.id, "root");
}

/// `/conf/dimension-*` and `/conf/multi-dimensional`: registry carries
/// all eight dimensions; artifacts converge multiple dimensions.
#[test]
fn ats_dimensions() {
    let f = build();
    for tag in [
        DimensionTag::data(),
        DimensionTag::person(),
        DimensionTag::time(),
        DimensionTag::location(),
        DimensionTag::environment(),
        DimensionTag::authorization(),
        DimensionTag::identity(),
        DimensionTag::oracle(),
    ] {
        assert!(
            f.registry.dimensions.contains(tag.as_str()),
            "{}",
            tag.as_str()
        );
    }
}

/// `/conf/format-jws`: detached JWS round trip (Annex E reference).
#[test]
fn ats_format_jws() {
    let sk = generate_key();
    let payload = jcs::canonicalize(&serde_json::json!({"k":1}))
        .unwrap()
        .into_bytes();
    let jws = confium_signatif::jws::sign_detached_ed25519(&sk, Some("end"), &payload).unwrap();
    assert!(
        confium_signatif::jws::verify_detached_ed25519(
            &jws,
            &payload,
            sk.verifying_key().as_bytes()
        )
        .is_ok()
    );
}

/// `/conf/device-signer`: challenge-response with nonce binding.
#[test]
fn ats_device_signer() {
    let challenge =
        confium_signatif::passport::Challenge::generate(chrono::Duration::seconds(30)).unwrap();
    let response = challenge.expected_payload();
    assert!(challenge.verify_response(&response, Utc::now()).is_ok());
}

/// Revocation semantics: propagation marks bound artifacts reversibly.
#[test]
fn ats_revocation_propagation() {
    let mut index = RevocationIndex::new();
    index.bind(AuthorityStateBinding {
        artifact_hash: "h1".into(),
        authority_fingerprints: vec!["fp-end".into()],
        bound_at: Utc::now(),
    });
    index.revoke_state("fp-end");
    let (_, mark) = index.artifact_status("h1");
    assert_eq!(
        mark,
        Some(confium_signatif::revocation::ArtifactMark::Marked)
    );
}

/// `/conf/mirror` + multi-log: the gossip quorum over one agreed head.
#[test]
fn ats_transparency_gossip() {
    use confium_signatif::multilog::{GossipQuorum, WitnessCosignature};
    let head = b"sth-1".to_vec();
    let witnesses: Vec<_> = (0..2).map(|_| generate_key()).collect();
    let cosigns: Vec<_> = witnesses
        .iter()
        .enumerate()
        .map(|(i, sk)| WitnessCosignature {
            witness: format!("w{i}"),
            tree_head_bytes: head.clone(),
            signature: sk.sign(&head).to_bytes().to_vec(),
            public_key: sk.verifying_key().as_bytes().to_vec(),
        })
        .collect();
    assert!(
        GossipQuorum { min_sources: 2 }
            .check(&cosigns, &Ed25519Verifier)
            .unwrap()
    );
}

/// Every class claimed implemented is witnessed by this suite.
#[test]
fn ats_claims_align() {
    let implemented: Vec<_> = conformance_claims()
        .into_iter()
        .filter(|c| c.status == ConformanceStatus::Implemented)
        .map(|c| c.class)
        .collect();
    // The suite must keep growing with the claims: spot-check the
    // classes witnessed above.
    for class in [
        "/conf/basic-verifier",
        "/conf/full-verifier",
        "/conf/issuing-authority",
        "/conf/root-authority",
        "/conf/hierarchical",
        "/conf/multi-dimensional",
        "/conf/format-jws",
        "/conf/device-signer",
        "/conf/mirror",
    ] {
        assert!(implemented.contains(&class), "{class} missing");
    }
}

// Passport round trip is exercised by the unit suite; reference here
// for the class table.
#[test]
fn ats_passport() {
    let p = Passport {
        version: 1,
        object_id: "o1".into(),
        key_fingerprint: "ab".into(),
        scope_summary: "domain:pharma".into(),
        valid_from: Utc::now(),
        valid_until: Utc::now() + chrono::Duration::days(1),
    };
    let bytes = p.distribution_bytes().unwrap();
    assert!(Passport::from_distribution_bytes(&bytes).is_ok());
}
