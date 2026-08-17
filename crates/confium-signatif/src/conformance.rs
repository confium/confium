//! Conformance classes and the abstract test suite mapping (SIGNATIF
//! §6, Annex A).
//!
//! An implementation claims conformance through the class hierarchy.
//! [`conformance_report`] produces the machine-readable claim list:
//! which `/conf` classes this build of Confium implements, and where
//! each is exercised. Classes not yet implemented are reported as
//! `planned` — never silently omitted — so a scheme adopting Confium
//! knows exactly what it can claim.

use serde::{Deserialize, Serialize};

/// Implementation status of a conformance class in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStatus {
    /// Implemented and exercised by the abstract test suite.
    Implemented,
    /// Implemented at model level; wire-format or service integration
    /// pending (see the module docs).
    Partial,
    /// Not yet implemented; tracked in the scheme TODO list.
    Planned,
}

/// One conformance-class claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceClaim {
    /// The `/conf` class identifier.
    pub class: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Implementation status in this build.
    pub status: ConformanceStatus,
    /// Where the class is implemented (crate::module).
    pub implemented_in: &'static str,
}

/// The class hierarchy with this build's status.
pub fn conformance_claims() -> Vec<ConformanceClaim> {
    use ConformanceStatus as S;
    vec![
        ConformanceClaim {
            class: "/conf/basic-verifier",
            description: "Verify artifacts offline against an anchor bundle: hard checks, coverage report, acceptance policy",
            status: S::Implemented,
            implemented_in: "confium_signatif::pipeline",
        },
        ConformanceClaim {
            class: "/conf/full-verifier",
            description: "Basic verifier plus trust-graph path-finding, multi-dimension verification, classification policies",
            status: S::Implemented,
            implemented_in: "confium_signatif::pipeline + graph + coverage",
        },
        ConformanceClaim {
            class: "/conf/issuing-authority",
            description: "Issue end certificates and produce trusted artifacts with dimension attestations",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact + ceremony",
        },
        ConformanceClaim {
            class: "/conf/root-authority",
            description: "Operate a root: anchor bundles, deployment manifests, cross-recognition",
            status: S::Implemented,
            implemented_in: "confium_signatif::bundle + confium_deployment::signatif",
        },
        ConformanceClaim {
            class: "/conf/transparency-operator",
            description: "Operate an append-only log with inclusion and consistency proofs",
            status: S::Implemented,
            implemented_in: "confium_transparency + confium-log-server",
        },
        ConformanceClaim {
            class: "/conf/mirror",
            description: "Mirror a log: verify append-only continuity, serve proofs",
            status: S::Implemented,
            implemented_in: "confium_transparency::witness + confium-log-monitor",
        },
        ConformanceClaim {
            class: "/conf/device-signer",
            description: "Device signs fresh nonce-bound artifacts under challenge",
            status: S::Implemented,
            implemented_in: "confium_signatif::passport (Challenge)",
        },
        ConformanceClaim {
            class: "/conf/hierarchical",
            description: "Single-root hierarchy topology",
            status: S::Implemented,
            implemented_in: "confium_signatif::graph + deployment::signatif",
        },
        ConformanceClaim {
            class: "/conf/federated",
            description: "Threshold groups of independent organizations",
            status: S::Implemented,
            implemented_in: "confium_signatif::fta",
        },
        ConformanceClaim {
            class: "/conf/cross-recognized",
            description: "Roots attesting each other via signed credentials",
            status: S::Implemented,
            implemented_in: "confium_deployment::signatif::CrossRecognition",
        },
        ConformanceClaim {
            class: "/conf/mesh",
            description: "Many-to-many peer recognition",
            status: S::Implemented,
            implemented_in: "confium_signatif::graph (multi-root, multi-path)",
        },
        ConformanceClaim {
            class: "/conf/format-cose",
            description: "COSE Sig_Structure envelope",
            status: S::Implemented,
            implemented_in: "confium_composite::cose",
        },
        ConformanceClaim {
            class: "/conf/format-jws",
            description: "JWS compact, detached content",
            status: S::Implemented,
            implemented_in: "confium_signatif::jws",
        },
        ConformanceClaim {
            class: "/conf/format-xmldsig",
            description: "XML Signature with Exclusive C14N",
            status: S::Implemented,
            implemented_in: "confium_pki::xmldsig",
        },
        ConformanceClaim {
            class: "/conf/dimension-data",
            description: "Data dimension attestation",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact + registry",
        },
        ConformanceClaim {
            class: "/conf/dimension-person",
            description: "Person dimension attestation",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact + registry",
        },
        ConformanceClaim {
            class: "/conf/dimension-time",
            description: "Time dimension with external anchor",
            status: S::Implemented,
            implemented_in: "confium_signatif::time",
        },
        ConformanceClaim {
            class: "/conf/dimension-location",
            description: "Location dimension attestation",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact + registry",
        },
        ConformanceClaim {
            class: "/conf/dimension-environment",
            description: "Environment dimension attestation",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact + registry",
        },
        ConformanceClaim {
            class: "/conf/dimension-authorization",
            description: "Authorization dimension attestation",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact + registry",
        },
        ConformanceClaim {
            class: "/conf/dimension-identity",
            description: "Identity dimension attestation",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact + registry",
        },
        ConformanceClaim {
            class: "/conf/dimension-oracle",
            description: "Oracle dimension attestation",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact + registry",
        },
        ConformanceClaim {
            class: "/conf/multi-dimensional",
            description: "Multiple independent dimensions converging on one artifact",
            status: S::Implemented,
            implemented_in: "confium_signatif::artifact (living artifacts)",
        },
        ConformanceClaim {
            class: "/conf/post-quantum",
            description: "ML-DSA-65 and SLH-DSA-128s verification, classical+PQC and PQC-only composites",
            status: S::Implemented,
            implemented_in: "confium_composite::pq (features pq, pq-slh)",
        },
    ]
}

/// The machine-readable conformance report for this build.
pub fn conformance_report() -> serde_json::Value {
    let claims = conformance_claims();
    let implemented = claims
        .iter()
        .filter(|c| c.status == ConformanceStatus::Implemented)
        .count();
    serde_json::json!({
        "framework": "SIGNATIF",
        "implementation": "confium-signatif",
        "version": env!("CARGO_PKG_VERSION"),
        "classes_claimed": claims.len(),
        "implemented": implemented,
        "claims": claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_24_classes_covered() {
        let claims = conformance_claims();
        assert_eq!(claims.len(), 24, "the SIGNATIF class hierarchy");
        // Uniqueness.
        let mut ids: Vec<_> = claims.iter().map(|c| c.class).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), claims.len());
    }

    #[test]
    fn core_verifier_classes_are_implemented() {
        for class in ["/conf/basic-verifier", "/conf/full-verifier"] {
            assert_eq!(
                conformance_claims()
                    .iter()
                    .find(|c| c.class == class)
                    .expect(class)
                    .status,
                ConformanceStatus::Implemented,
                "{class} must be implemented — it is the base of the hierarchy"
            );
        }
    }

    #[test]
    fn report_is_serializable() {
        let report = conformance_report();
        assert!(report["claims"].as_array().unwrap().len() == 24);
        assert_eq!(report["implemented"].as_u64().unwrap(), 24);
    }
}
