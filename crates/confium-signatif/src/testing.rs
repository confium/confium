//! Specimen builders for the abstract test suite.
//!
//! Building one valid trusted artifact means generating keys,
//! assembling a trust graph, signing an anchor bundle, and
//! co-signing the artifact — work every test surface (the Rust
//! suites, the browser binding, examples) used to duplicate. This
//! module owns the specimen kit so suites compose from it instead.
//!
//! The module ships in the published crate on purpose: a separate
//! test-support crate consumed as a dev-dependency would recreate the
//! publish ordering deadlock (published crates must never
//! dev-depend on a later-publishing workspace crate). It adds no
//! dependencies beyond what `confium-signatif` already links.

use ed25519_dalek::Signer;

use crate::artifact::TrustedArtifact;
use crate::bundle::{AnchorRoot, TrustAnchorBundle};
use crate::graph::{AuthorityKind, AuthorityNode, DelegationEdge, TrustGraph};
use crate::registry::{DimensionTag, Registry};
use crate::scope::ScopeDimensions;

/// A valid specimen: root-delegated end authority, signed anchor
/// bundle, and a data-dimension co-signed artifact over it, plus the
/// secret keys so tests can sign more, tamper, or re-issue.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// The co-signed trusted artifact.
    pub artifact: TrustedArtifact,
    /// The signed trust anchor bundle anchoring `root`.
    pub bundle: TrustAnchorBundle,
    /// The root → end delegation graph.
    pub graph: TrustGraph,
    /// The registry the artifact was signed under.
    pub registry: Registry,
    /// The root authority's signing key.
    pub root_secret: ed25519_dalek::SigningKey,
    /// The end authority's signing key (the artifact's co-signer).
    pub end_secret: ed25519_dalek::SigningKey,
}

impl Fixture {
    /// Build a fresh valid specimen with random keys.
    pub fn valid() -> Fixture {
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        let root_secret = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        let end_secret = ed25519_dalek::SigningKey::from_bytes(&seed);

        let registry = Registry::with_initial_values();
        let root = AuthorityNode {
            id: "root".into(),
            kind: AuthorityKind::Root,
            public_key: root_secret.verifying_key().as_bytes().to_vec(),
            quorum: None,
            scope: ScopeDimensions::unconstrained(),
        };
        let end = AuthorityNode {
            id: "end".into(),
            kind: AuthorityKind::EndCertificate,
            public_key: end_secret.verifying_key().as_bytes().to_vec(),
            quorum: None,
            scope: ScopeDimensions::unconstrained(),
        };
        let mut graph = TrustGraph::new();
        graph.add_node(root.clone());
        graph.add_node(end.clone());
        graph
            .add_delegation(DelegationEdge {
                parent: "root".into(),
                child: "end".into(),
                signature: root_secret
                    .sign(&end.binding_bytes().unwrap())
                    .to_bytes()
                    .to_vec(),
            })
            .unwrap();

        let bundle = Self::sign_bundle(
            root.public_key.clone(),
            &root_secret,
            chrono::Utc::now() - chrono::Duration::hours(1),
            chrono::Utc::now() + chrono::Duration::days(30),
        );

        let mut artifact = TrustedArtifact::new(
            crate::artifact::ArtifactVersion { major: 1, minor: 0 },
            "fixture-1",
            serde_json::json!({"dose": 500}),
            None,
        )
        .unwrap();
        artifact
            .sign(
                DimensionTag::data(),
                "Ed25519",
                "end",
                end_secret.verifying_key().as_bytes().to_vec(),
                "root",
                &|m| end_secret.sign(m).to_bytes().to_vec(),
                &registry,
            )
            .unwrap();

        Fixture {
            artifact,
            bundle,
            graph,
            registry,
            root_secret,
            end_secret,
        }
    }

    fn sign_bundle(
        root_key: Vec<u8>,
        root_secret: &ed25519_dalek::SigningKey,
        valid_from: chrono::DateTime<chrono::Utc>,
        valid_until: chrono::DateTime<chrono::Utc>,
    ) -> TrustAnchorBundle {
        let mut bundle = TrustAnchorBundle {
            bundle_version: "1".into(),
            valid_from,
            valid_until,
            roots: vec![AnchorRoot {
                name: "root".into(),
                aggregate_key: root_key.clone(),
                fingerprint: hex::encode(&root_key),
                quorum: None,
            }],
            transparency_logs: vec![],
            update_log: None,
            bundle_signature: vec![],
        };
        let msg = bundle.signing_bytes().unwrap();
        bundle.bundle_signature = root_secret.sign(&msg).to_bytes().to_vec();
        bundle
    }

    /// The same artifact with a mutated payload: signature-validity
    /// hard check must fail.
    pub fn tampered_artifact(&self) -> TrustedArtifact {
        let mut value = serde_json::to_value(&self.artifact).unwrap();
        value["payload"]["dose"] = serde_json::json!(999);
        serde_json::from_value(value).unwrap()
    }

    /// The same anchors in a bundle whose validity window has closed:
    /// the bundle-validity hard check must fail.
    pub fn expired_bundle(&self) -> TrustAnchorBundle {
        Self::sign_bundle(
            self.root_secret.verifying_key().as_bytes().to_vec(),
            &self.root_secret,
            chrono::Utc::now() - chrono::Duration::days(30),
            chrono::Utc::now() - chrono::Duration::hours(1),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{VerifyOptions, verify_trusted_artifact};

    #[test]
    fn valid_specimen_ladders() {
        let f = Fixture::valid();
        let options = VerifyOptions {
            transparency_included: true,
            time_anchored: true,
            time_attested_at: Some(chrono::Utc::now().to_rfc3339()),
            accepted_labels: vec!["verified".into()],
            ..VerifyOptions::default()
        };
        let verdict =
            verify_trusted_artifact(&f.artifact, &f.bundle, &f.graph, &f.registry, &options)
                .unwrap();
        assert_eq!(verdict.label, "verified");
        assert!(verdict.accept);
    }

    #[test]
    fn tampered_specimen_hard_fails() {
        let f = Fixture::valid();
        let err = verify_trusted_artifact(
            &f.tampered_artifact(),
            &f.bundle,
            &f.graph,
            &f.registry,
            &VerifyOptions::default(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("signature_validity"), "{err}");
    }

    #[test]
    fn expired_specimen_hard_fails() {
        let f = Fixture::valid();
        let err = verify_trusted_artifact(
            &f.artifact,
            &f.expired_bundle(),
            &f.graph,
            &f.registry,
            &VerifyOptions::default(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("bundle"), "{err}");
    }
}
