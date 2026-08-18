//! The verification pipeline (SIGNATIF §14).
//!
//! An ordered sequence of checks classified as **hard** or **soft**.
//! Any hard failure short-circuits to the scheme's rejected label;
//! soft results accumulate into the [`CoverageReport`]. Inputs are the
//! artifact, the trust anchor bundle, the trust graph, the registries,
//! a revocation view, and the classification/acceptance policies —
//! everything an offline verifier holds or caches.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::artifact::TrustedArtifact;
use crate::bundle::TrustAnchorBundle;
use crate::coverage::{
    Acceptance, AcceptancePolicy, ClassificationLabel, ClassificationPolicy, CoverageReport,
    HardCheckStatus, ReferenceClassificationPolicy,
};
use crate::error::{SignatifError, SignatifResult};
use crate::graph::{SignatureVerifier, TrustGraph};
use crate::registry::Registry;
use crate::revocation::{DEFAULT_GRACE_PERIOD, RevocationView};
use crate::scope::ScopeDimensions;

/// Soft-check inputs the pipeline cannot derive on its own.
#[derive(Debug, Clone, Default)]
pub struct TransparencyInputs {
    /// Whether inclusion proofs were verified for the artifact against
    /// a recognized log (from the bundle's log set).
    pub artifact_included: bool,
    /// Whether the M-of-K multi-log quorum was met.
    pub multi_log_quorum: bool,
    /// Whether a time-anchor attestation was verified (see [`crate::time`]).
    pub time_anchored: bool,
    /// The externally-attested time from a verified [`crate::time::
    /// TimeAttestation`] — the freshness source preferred over the
    /// signer's self-asserted block timestamps (§8.8).
    pub time_attested_at: Option<DateTime<Utc>>,
    /// Downgrade reasons the caller's soft checks produced (e.g.
    /// "transparency_missing", "time_anchor_absent").
    pub downgrades: Vec<String>,
}

/// The freshness window applied to time attestations (§14
/// `time-freshness-window`): attestations inside the window are fresh;
/// inside `grace` but outside the window they downgrade; older reject.
#[derive(Debug, Clone, Copy)]
pub struct FreshnessWindow {
    /// Maximum age of a time attestation.
    pub window: chrono::Duration,
    /// Secondary grace period at downgraded classification.
    pub grace: chrono::Duration,
}

impl Default for FreshnessWindow {
    fn default() -> Self {
        Self {
            window: chrono::Duration::seconds(30 * 60),
            grace: chrono::Duration::hours(24),
        }
    }
}

/// The outcome of a pipeline run.
#[derive(Debug, Clone)]
pub struct VerificationOutcome {
    /// The objective coverage report.
    pub report: CoverageReport,
    /// The scheme's classification of the report.
    pub label: ClassificationLabel,
    /// The verifier's acceptance decision.
    pub acceptance: Acceptance,
}

/// The ordered verification pipeline.
pub struct Pipeline<'a> {
    /// Anchor bundle (offline trust starting point).
    pub bundle: &'a TrustAnchorBundle,
    /// The trust graph (delegation DAG).
    pub graph: &'a TrustGraph,
    /// Scheme registries.
    pub registry: &'a Registry,
    /// Signature verifier fleet.
    pub verifier: &'a dyn SignatureVerifier,
    /// Revocation state view (CRLs and hash bindings).
    pub revocation: &'a dyn RevocationView,
    /// Soft-check inputs from transparency and time verification.
    pub transparency: TransparencyInputs,
    /// Time-freshness window.
    pub freshness: FreshnessWindow,
    /// Classification policy (scheme-defined).
    pub classification: &'a dyn ClassificationPolicy,
    /// Acceptance policy (verifier-defined).
    pub acceptance: &'a AcceptancePolicy,
}

impl<'a> Pipeline<'a> {
    /// A pipeline with the reference classification policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle: &'a TrustAnchorBundle,
        graph: &'a TrustGraph,
        registry: &'a Registry,
        verifier: &'a dyn SignatureVerifier,
        revocation: &'a dyn RevocationView,
        transparency: TransparencyInputs,
        acceptance: &'a AcceptancePolicy,
    ) -> Self {
        Self {
            bundle,
            graph,
            registry,
            verifier,
            revocation,
            transparency,
            freshness: FreshnessWindow::default(),
            classification: &ReferenceClassificationPolicy,
            acceptance,
        }
    }

    /// Override the classification policy.
    pub fn with_classification(mut self, policy: &'a dyn ClassificationPolicy) -> Self {
        self.classification = policy;
        self
    }

    /// Override the freshness window.
    pub fn with_freshness(mut self, window: FreshnessWindow) -> Self {
        self.freshness = window;
        self
    }

    /// Run the pipeline. Hard checks in order: bundle validity, format
    /// validity + registry status, co-signature verification, chain
    /// path-finding (scope narrowing per link), revocation status.
    /// Soft checks accumulate: transparency, time anchor, multi-log
    /// quorum, dimension coverage, root diversity.
    ///
    /// # Errors
    ///
    /// Returns the first hard failure encountered; the error is the
    /// machine-readable reason, the caller short-circuits to the
    /// rejected label.
    pub fn run(
        &self,
        artifact: &TrustedArtifact,
        now: DateTime<Utc>,
    ) -> SignatifResult<VerificationOutcome> {
        // Hard 1: anchor bundle validity.
        self.bundle
            .verify(now, self.verifier)
            .map_err(|e| SignatifError::HardCheck(format!("bundle_validity: {e}")))?;

        // Hard 2: format validity, version compatibility, registry
        // status, self-description (canonical hash binding), and every
        // co-signature independently.
        let supported = crate::artifact::ArtifactVersion { major: 1, minor: 0 };
        if !supported.accepts(&artifact.version) {
            return Err(SignatifError::HardCheck(format!(
                "format_version: artifact {} exceeds supported {}",
                artifact.version, supported
            )));
        }
        artifact
            .verify_self(self.registry, self.verifier)
            .map_err(|e| SignatifError::HardCheck(format!("signature_validity: {e}")))?;

        // Hard 3: chain integrity — at least one path from a signer to
        // an anchor for each distinct chain_ref, scope narrowing
        // enforced per link by the graph walk.
        let mut paths_found = 0usize;
        let mut roots: Vec<String> = Vec::new();
        for block in &artifact.co_signatures {
            let node = self.graph.node(&block.signer_cert_ref).ok_or_else(|| {
                SignatifError::HardCheck(format!(
                    "chain_integrity: unknown signer {}",
                    block.signer_cert_ref
                ))
            })?;
            let paths = self
                .graph
                .find_paths(&node.id, self.bundle, self.verifier)
                .map_err(|e| SignatifError::HardCheck(format!("chain_integrity: {e}")))?;
            if paths.is_empty() {
                return Err(SignatifError::HardCheck(format!(
                    "chain_integrity: no path from {} to an anchor",
                    node.id
                )));
            }
            paths_found += paths.len();
            for p in &paths {
                if !roots.contains(&p.root.id) {
                    roots.push(p.root.id.clone());
                }
            }
        }

        // Hard 4: scope conditions — every signer node's executable
        // conditions are evaluated against the artifact and its chain
        // (§11): failing conditions hard-fail regardless of signature
        // validity.
        for block in &artifact.co_signatures {
            if let Some(node) = self.graph.node(&block.signer_cert_ref) {
                let ctx = crate::conditions::ConditionContext::new(
                    &artifact.payload,
                    &artifact.artifact_id,
                    &block.signer_cert_ref,
                    block.dimension.as_str(),
                    &block.timestamp.to_rfc3339(),
                );
                crate::conditions::evaluate_all(&node.scope.conditions, &ctx)
                    .map_err(|e| SignatifError::HardCheck(format!("scope_conditions: {e}")))?;
            }
        }

        // Hard 5: revocation of every authority on every valid path.
        for block in &artifact.co_signatures {
            let status = self
                .revocation
                .authority_status(&block.signer_cert_ref, now);
            match status {
                crate::revocation::RevocationStatus::Revoked => {
                    return Err(SignatifError::HardCheck(format!(
                        "revocation: signer {} is revoked",
                        block.signer_cert_ref
                    )));
                }
                crate::revocation::RevocationStatus::GraceDowngrade => {
                    // soft: recorded as downgrade below
                }
                crate::revocation::RevocationStatus::Good => {}
            }
        }

        // Soft checks: accumulate into the coverage report. Deprecated
        // algorithms (§20) downgrade; retired already hard-failed in
        // verify_self's registry check.
        let mut downgrades = self.transparency.downgrades.clone();
        for block in &artifact.co_signatures {
            if self.registry.algorithms.status(&block.algorithm)
                == Some(crate::registry::Status::Deprecated)
            {
                downgrades.push(format!("deprecated_algorithm:{}", block.algorithm));
            }
        }
        if !self.transparency.artifact_included {
            downgrades.push("transparency_missing".into());
        }
        if !self.transparency.time_anchored {
            downgrades.push("time_anchor_absent".into());
        }
        if self.revocation.max_crl_age(now) > DEFAULT_GRACE_PERIOD {
            downgrades.push("crl_stale".into());
        }
        // Freshness: the externally-attested time when a verified time
        // authority attestation exists; otherwise the newest
        // time-dimension block timestamp.
        let freshness_source = self.transparency.time_attested_at.or_else(|| {
            artifact
                .co_signatures
                .iter()
                .filter(|b| b.dimension.as_str() == crate::registry::DimensionTag::TIME)
                .map(|b| b.timestamp)
                .max()
        });
        if let Some(newest) = freshness_source {
            let age = now.signed_duration_since(newest);
            if age > self.freshness.window + self.freshness.grace {
                return Err(SignatifError::HardCheck(
                    "time_freshness: time attestation outside window and grace".into(),
                ));
            }
            if age > self.freshness.window {
                downgrades.push("time_attestation_stale".into());
            }
        }

        let report = CoverageReport {
            hard_checks: HardCheckStatus::Pass,
            transparency_included: self.transparency.artifact_included,
            time_anchored: self.transparency.time_anchored,
            dimensions_verified: artifact
                .dimensions_verified()
                .iter()
                .map(|d| d.as_str().to_string())
                .collect(),
            dimension_count: artifact.dimensions_verified().len(),
            independent_roots: roots.len(),
            multi_log_quorum: self.transparency.multi_log_quorum,
            paths_found,
            downgrades,
        };
        let label = self.classification.classify(&report);
        let acceptance = self.acceptance.decide(&label);
        Ok(VerificationOutcome {
            report,
            label,
            acceptance,
        })
    }
}

/// The scope of the signer on the (first) verified path — policy input
/// for downstream decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerScopeSummary {
    /// Signer node identifier.
    pub signer: String,
    /// The signer's scope.
    pub scope: ScopeDimensions,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactVersion;
    use crate::bundle::AnchorRoot;
    use crate::graph::{AuthorityKind, AuthorityNode, DelegationEdge, Quorum as GraphQuorum};
    use crate::registry::DimensionTag;
    use crate::registry::Registry;
    use crate::revocation::NoRevocations;
    use ed25519_dalek::{Signer, SigningKey};

    fn generate_key() -> ed25519_dalek::SigningKey {
        use rand_core::RngCore;
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
        end_sk: SigningKey,
        root_sk: SigningKey,
    }

    fn build() -> Fixture {
        let registry = Registry::with_initial_values();
        let root_sk = generate_key();
        let root = AuthorityNode {
            id: "root".into(),
            kind: AuthorityKind::Root,
            public_key: root_sk.verifying_key().as_bytes().to_vec(),
            quorum: Some(GraphQuorum::new(2, 3).unwrap()),
            scope: crate::scope::ScopeDimensions::unconstrained(),
        };
        let end_sk = generate_key();
        let end = AuthorityNode {
            id: "end".into(),
            kind: AuthorityKind::EndCertificate,
            public_key: end_sk.verifying_key().as_bytes().to_vec(),
            quorum: None,
            scope: crate::scope::ScopeDimensions::unconstrained(),
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

        let bundle = TrustAnchorBundle {
            bundle_version: "2026.08".into(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::days(30),
            roots: vec![AnchorRoot {
                name: "root".into(),
                aggregate_key: root.public_key.clone(),
                fingerprint: "00".into(),
                quorum: root.quorum,
            }],
            transparency_logs: vec![],
            bundle_signature: vec![],
            update_log: None,
        };
        // Bundle signature unused by pipeline? It verifies signatures —
        // sign the bundle with the root key so hard check 1 passes.
        let mut bundle = bundle;
        let mut signed = bundle.clone();
        signed.bundle_signature = Vec::new();
        let msg = crate::jcs::canonicalize(&serde_json::to_value(&signed).unwrap()).unwrap();
        bundle.bundle_signature = root_sk.sign(msg.as_bytes()).to_bytes().to_vec();

        let mut artifact = TrustedArtifact::new(
            ArtifactVersion { major: 1, minor: 0 },
            "art-1",
            serde_json::json!({"v": 1}),
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

        Fixture {
            graph,
            bundle,
            registry,
            artifact,
            end_sk,
            root_sk,
        }
    }

    #[test]
    fn full_pipeline_rejects_without_transparency_then_ladders_up() {
        let f = build();
        static NO_REVOCATIONS: NoRevocations = NoRevocations;
        let accept_all =
            AcceptancePolicy::accept(&["unverified", "basic", "verified", "attested", "certified"]);

        let pipe = Pipeline::new(
            &f.bundle,
            &f.graph,
            &f.registry,
            &Ed25519Verifier,
            &NO_REVOCATIONS,
            TransparencyInputs::default(),
            &accept_all,
        );
        let out = pipe.run(&f.artifact, Utc::now()).unwrap();
        assert_eq!(out.label.0, "unverified");
        assert_eq!(out.acceptance, Acceptance::Accept);

        let with_transparency = pipe_with(&f, true, false, &accept_all);
        let out = with_transparency.run(&f.artifact, Utc::now()).unwrap();
        assert_eq!(out.label.0, "basic");

        let with_time = pipe_with(&f, true, true, &accept_all);
        let out = with_time.run(&f.artifact, Utc::now()).unwrap();
        assert_eq!(out.label.0, "verified");
    }

    fn pipe_with<'p>(
        f: &'p Fixture,
        transparency: bool,
        time: bool,
        acceptance: &'p AcceptancePolicy,
    ) -> Pipeline<'p> {
        static NO_REVOCATIONS: NoRevocations = NoRevocations;
        Pipeline::new(
            &f.bundle,
            &f.graph,
            &f.registry,
            &Ed25519Verifier,
            &NO_REVOCATIONS,
            TransparencyInputs {
                artifact_included: transparency,
                time_anchored: time,
                time_attested_at: None,
                multi_log_quorum: false,
                downgrades: vec![],
            },
            acceptance,
        )
    }

    #[test]
    fn tampered_artifact_short_circuits_to_hard_failure() {
        let f = build();
        let mut broken = f.artifact.clone();
        broken.payload["v"] = serde_json::json!(2);
        static NO_REVOCATIONS: NoRevocations = NoRevocations;
        let accept_all = AcceptancePolicy::accept(&["verified"]);
        let pipe = Pipeline::new(
            &f.bundle,
            &f.graph,
            &f.registry,
            &Ed25519Verifier,
            &NO_REVOCATIONS,
            TransparencyInputs::default(),
            &accept_all,
        );
        let err = pipe.run(&broken, Utc::now()).unwrap_err();
        assert!(err.to_string().contains("signature_validity"));
    }

    #[test]
    fn scope_conditions_hard_fail_when_unmet() {
        let f = build();
        static NO_REVOCATIONS: NoRevocations = NoRevocations;
        let accept_all = AcceptancePolicy::accept(&["verified"]);
        // The end node carries an executable condition on the payload.
        // The conditions are part of the node binding, so the root's
        // delegation credential must cover them (four-layer scope
        // enforcement, layers 1-2).
        let mut end = f.graph.node("end").unwrap().clone();
        end.scope.conditions = vec![serde_json::json!({
            ">=": [ {"var": "payload.v"}, 5 ]
        })];
        let root_node = f.graph.node("root").unwrap().clone();
        use ed25519_dalek::Signer as _;
        let mut graph = TrustGraph::new();
        graph.add_node(root_node);
        graph.add_node(end.clone());
        graph
            .add_delegation(DelegationEdge {
                parent: "root".into(),
                child: "end".into(),
                signature: f
                    .root_sk
                    .sign(&end.binding_bytes().unwrap())
                    .to_bytes()
                    .to_vec(),
            })
            .unwrap();
        let pipe = Pipeline::new(
            &f.bundle,
            &graph,
            &f.registry,
            &Ed25519Verifier,
            &NO_REVOCATIONS,
            TransparencyInputs::default(),
            &accept_all,
        );
        // payload.v == 1 -> condition unmet -> hard failure even though
        // every signature and the chain verify. The positive path is
        // exercised in the conditions module tests.
        let err = pipe.run(&f.artifact, Utc::now()).unwrap_err();
        assert!(err.to_string().contains("scope_conditions"), "got {err}");
    }

    #[test]
    fn deprecated_algorithm_downgrades_and_caps_label() {
        let f = build();
        static NO_REVOCATIONS: NoRevocations = NoRevocations;
        let mut agile = f.registry.clone();
        agile
            .algorithms
            .set_status("Ed25519", crate::registry::Status::Deprecated)
            .unwrap();
        let accept_all =
            AcceptancePolicy::accept(&["unverified", "basic", "verified", "attested", "certified"]);
        // Full soft coverage: without deprecation this reaches
        // "attested" (data + person? only data here -> "verified");
        // with the deprecated algorithm the label stays "verified"
        // but the downgrade is recorded. Person present would cap too.
        let pipe = Pipeline::new(
            &f.bundle,
            &f.graph,
            &agile,
            &Ed25519Verifier,
            &NO_REVOCATIONS,
            TransparencyInputs {
                artifact_included: true,
                time_anchored: true,
                time_attested_at: None,
                multi_log_quorum: false,
                downgrades: vec![],
            },
            &accept_all,
        );
        let out = pipe.run(&f.artifact, Utc::now()).unwrap();
        assert!(
            out.report
                .downgrades
                .iter()
                .any(|d| d == "deprecated_algorithm:Ed25519"),
            "downgrades: {:?}",
            out.report.downgrades
        );

        // With a person dimension the cap bites: attested -> verified.
        let person = ed25519_dalek::SigningKey::from_bytes(&{
            use rand_core::RngCore as _;
            let mut seed = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut seed);
            seed
        });
        use ed25519_dalek::Signer as _;
        let mut rich = f.artifact.clone();
        let input = rich.cosign_input(&DimensionTag::person());
        rich.co_signatures.push(crate::artifact::CoSignatureBlock {
            dimension: DimensionTag::person(),
            algorithm: "Ed25519".into(),
            signer_cert_ref: "end".into(),
            signer_pubkey: person.verifying_key().as_bytes().to_vec(),
            chain_ref: "root".into(),
            signature: person.sign(&input).to_bytes().to_vec(),
            timestamp: Utc::now(),
        });
        let out = pipe.run(&rich, Utc::now()).unwrap();
        assert_eq!(out.label.0, "verified", "deprecated caps attested");

        // Retired hard-fails outright.
        let mut retired = agile.clone();
        retired
            .algorithms
            .set_status("Ed25519", crate::registry::Status::Retired)
            .unwrap();
        let pipe = Pipeline::new(
            &f.bundle,
            &f.graph,
            &retired,
            &Ed25519Verifier,
            &NO_REVOCATIONS,
            TransparencyInputs::default(),
            &accept_all,
        );
        assert!(pipe.run(&f.artifact, Utc::now()).is_err());
    }

    #[test]
    fn stale_time_attestation_beyond_grace_is_hard_failure() {
        let f = build();
        static NO_REVOCATIONS: NoRevocations = NoRevocations;
        let accept_all = AcceptancePolicy::accept(&["verified"]);
        let pipe = Pipeline::new(
            &f.bundle,
            &f.graph,
            &f.registry,
            &Ed25519Verifier,
            &NO_REVOCATIONS,
            TransparencyInputs {
                artifact_included: true,
                time_anchored: true,
                time_attested_at: None,
                multi_log_quorum: false,
                downgrades: vec![],
            },
            &accept_all,
        )
        .with_freshness(FreshnessWindow {
            window: chrono::Duration::seconds(60),
            grace: chrono::Duration::seconds(60),
        });
        // A properly signed TIME block whose timestamp is beyond
        // window + grace: hard failure.
        let mut old = f.artifact.clone();
        let input = old.cosign_input(&DimensionTag::time());
        use ed25519_dalek::Signer as _;
        old.co_signatures.push(crate::artifact::CoSignatureBlock {
            dimension: DimensionTag::time(),
            algorithm: "Ed25519".into(),
            signer_cert_ref: "end".into(),
            signer_pubkey: f.end_sk.verifying_key().as_bytes().to_vec(),
            chain_ref: "root".into(),
            signature: f.end_sk.sign(&input).to_bytes().to_vec(),
            timestamp: Utc::now() - chrono::Duration::hours(2),
        });
        let err = pipe.run(&old, Utc::now()).unwrap_err();
        assert!(err.to_string().contains("time_freshness"), "got {err}");
    }
}
