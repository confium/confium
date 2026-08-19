//! The deep verification entry: one interface for every surface.
//!
//! The [`Pipeline`] is the ordered hard/soft check engine, but its
//! constructor takes every dependency as a raw parameter, so each
//! transport adapter (browser WASM, HTTP, CLI, Python) used to
//! re-assemble the same wiring — a verifier fleet, a revocation view,
//! transparency inputs, an acceptance policy — just to reach it.
//! This module owns that assembly once.
//!
//! ```no_run
//! use confium_signatif::verify::{verify_trusted_artifact, VerifyOptions};
//! # use confium_signatif::artifact::TrustedArtifact;
//! # use confium_signatif::bundle::TrustAnchorBundle;
//! # use confium_signatif::graph::TrustGraph;
//! # use confium_signatif::registry::Registry;
//! # fn main() -> Result<(), confium_signatif::SignatifError> {
//! # let (artifact, bundle, graph, registry) = unimplemented!();
//! let options = VerifyOptions {
//!     transparency_included: true,
//!     accepted_labels: vec!["verified".into()],
//!     ..VerifyOptions::default()
//! };
//! let verdict = verify_trusted_artifact(&artifact, &bundle, &graph, &registry, &options)?;
//! assert!(verdict.accept);
//! # Ok(())
//! # }
//! ```
//!
//! Revocation checking currently runs with
//! [`NoRevocations`](crate::revocation::NoRevocations); this
//! function is the single place that changes when a surface grows a
//! revocation input. Schemes that need a [`CrlView`](crate::revocation::CrlView)
//! today assemble the [`Pipeline`] directly.

use serde::{Deserialize, Serialize};

use crate::artifact::TrustedArtifact;
use crate::bundle::TrustAnchorBundle;
use crate::coverage::{Acceptance, AcceptancePolicy, CoverageReport};
use crate::graph::{SignatureVerifier, TrustGraph};
use crate::pipeline::{Pipeline, TransparencyInputs};
use crate::registry::Registry;
use crate::{SignatifError, SignatifResult};

/// Which signature algorithms a verifier checks.
///
/// The fleet is scheme policy, not per-surface code: pick a variant
/// instead of hand-writing a [`SignatureVerifier`]. The seam stays
/// open — exotic fleets (threshold, HSM) still implement the trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fleet {
    /// Ed25519 only — the browser/WASM verifier profile.
    #[serde(rename = "ed25519")]
    Ed25519,
    /// Ed25519 or ECDSA-P256 — the classical algorithms of the
    /// default registry.
    #[serde(rename = "ed25519_p256")]
    Ed25519P256,
}

impl SignatureVerifier for Fleet {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match self {
            Fleet::Ed25519 => ed25519(public_key, message, signature),
            Fleet::Ed25519P256 => {
                ed25519(public_key, message, signature) || p256(public_key, message, signature)
            }
        }
    }
}

fn ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    confium_composite::ed25519_verifier(confium_composite::ED25519, public_key, message, signature)
        .is_ok()
}

fn p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    confium_composite::p256_verifier(
        confium_composite::ECDSA_P256,
        public_key,
        message,
        signature,
    )
    .is_ok()
}

/// The verification inputs a transport collects, in the shape every
/// surface already speaks: field names match the JSON options of the
/// HTTP endpoint, the browser binding, and the CLI flags.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VerifyOptions {
    /// Which algorithms the verifier fleet checks.
    pub fleet: Fleet,
    /// Transparency inclusion was verified for this artifact.
    pub transparency_included: bool,
    /// An external time anchor was verified.
    pub time_anchored: bool,
    /// Externally-attested time (RFC 3339) from a verified time
    /// authority.
    pub time_attested_at: Option<String>,
    /// The M-of-K multi-log quorum was met.
    pub multi_log_quorum: bool,
    /// Classification labels this verifier accepts (empty = reject
    /// everything).
    pub accepted_labels: Vec<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            fleet: Fleet::Ed25519P256,
            transparency_included: false,
            time_anchored: false,
            time_attested_at: None,
            multi_log_quorum: false,
            accepted_labels: Vec::new(),
        }
    }
}

/// The graduated verification outcome: the objective coverage report,
/// the scheme's classification label, and this verifier's acceptance
/// decision — the triple every surface serializes.
#[derive(Debug, Serialize)]
pub struct Verdict {
    /// The scheme's classification label.
    pub label: String,
    /// The verifier's acceptance decision.
    pub accept: bool,
    /// The objective coverage report.
    pub coverage: CoverageReport,
}

/// Verify one trusted artifact through the full pipeline.
///
/// This is the single entry every transport adapter calls; the
/// pipeline assembly (fleet, revocation view, transparency inputs,
/// acceptance policy) lives here and nowhere else.
///
/// # Errors
///
/// Input decoding failures (including a malformed `time_attested_at`)
/// and hard-check failures surface as [`SignatifError`]; the error
/// names the failing check.
pub fn verify_trusted_artifact(
    artifact: &TrustedArtifact,
    bundle: &TrustAnchorBundle,
    graph: &TrustGraph,
    registry: &Registry,
    options: &VerifyOptions,
) -> SignatifResult<Verdict> {
    let time_attested_at = match &options.time_attested_at {
        None => None,
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| SignatifError::Encoding(format!("time_attested_at: {e}")))?
                .with_timezone(&chrono::Utc),
        ),
    };
    let no_revocations = crate::revocation::NoRevocations;
    let acceptance = AcceptancePolicy {
        accepted_labels: options.accepted_labels.clone(),
    };
    let pipe = Pipeline::new(
        bundle,
        graph,
        registry,
        &options.fleet,
        &no_revocations,
        TransparencyInputs {
            artifact_included: options.transparency_included,
            time_anchored: options.time_anchored,
            time_attested_at,
            multi_log_quorum: options.multi_log_quorum,
            downgrades: vec![],
        },
        &acceptance,
    );
    let outcome = pipe.run(artifact, chrono::Utc::now())?;
    Ok(Verdict {
        label: outcome.label.0,
        accept: outcome.acceptance == Acceptance::Accept,
        coverage: outcome.report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        crate::artifact::TrustedArtifact,
        crate::bundle::TrustAnchorBundle,
        crate::graph::TrustGraph,
        crate::registry::Registry,
    ) {
        let f = crate::testing::Fixture::valid();
        (f.artifact, f.bundle, f.graph, f.registry)
    }

    #[test]
    fn verdict_ladders_and_accepts() {
        let (artifact, bundle, graph, registry) = fixture();
        let options = VerifyOptions {
            accepted_labels: vec!["unverified".into()],
            ..VerifyOptions::default()
        };
        let verdict =
            verify_trusted_artifact(&artifact, &bundle, &graph, &registry, &options).unwrap();
        assert_eq!(verdict.label, "unverified");
        assert!(verdict.accept);

        let options = VerifyOptions {
            transparency_included: true,
            time_anchored: true,
            time_attested_at: Some(chrono::Utc::now().to_rfc3339()),
            accepted_labels: vec!["verified".into()],
            ..VerifyOptions::default()
        };
        let verdict =
            verify_trusted_artifact(&artifact, &bundle, &graph, &registry, &options).unwrap();
        assert_eq!(verdict.label, "verified");
        assert!(verdict.accept);
    }

    #[test]
    fn tampered_artifact_hard_fails() {
        let (artifact, bundle, graph, registry) = fixture();
        let mut value = serde_json::to_value(&artifact).unwrap();
        value["payload"]["dose"] = serde_json::json!(999);
        let tampered: TrustedArtifact = serde_json::from_value(value).unwrap();
        let options = VerifyOptions::default();
        let err =
            verify_trusted_artifact(&tampered, &bundle, &graph, &registry, &options).unwrap_err();
        assert!(format!("{err}").contains("signature_validity"), "{err}");
    }

    #[test]
    fn malformed_time_is_an_input_error() {
        let (artifact, bundle, graph, registry) = fixture();
        let options = VerifyOptions {
            time_attested_at: Some("not-a-time".into()),
            ..VerifyOptions::default()
        };
        let err =
            verify_trusted_artifact(&artifact, &bundle, &graph, &registry, &options).unwrap_err();
        assert!(err.to_string().contains("time_attested_at"), "{err}");
    }

    #[test]
    fn options_deserialize_from_surface_json() {
        let json = r#"{
            "transparency_included": true,
            "time_anchored": true,
            "time_attested_at": "2026-08-19T00:00:00Z",
            "multi_log_quorum": false,
            "accepted_labels": ["verified"]
        }"#;
        let options: VerifyOptions = serde_json::from_str(json).unwrap();
        assert_eq!(options.fleet, Fleet::Ed25519P256);
        assert!(options.transparency_included);
        assert_eq!(options.accepted_labels, vec!["verified"]);

        let browser: VerifyOptions = serde_json::from_str(r#"{"fleet": "ed25519"}"#).unwrap();
        assert_eq!(browser.fleet, Fleet::Ed25519);
    }
}
