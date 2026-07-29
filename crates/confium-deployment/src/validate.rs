//! Manifest validation.

use crate::manifest::{DeploymentMode, Manifest};

#[derive(Debug, Clone, Default)]
pub struct ValidationReport {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn validate_manifest(manifest: &Manifest) -> ValidationReport {
    let mut report = ValidationReport {
        valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    if manifest.deployment.manifest_version != 1 {
        report.errors.push(format!(
            "unsupported manifest version {}",
            manifest.deployment.manifest_version
        ));
    }

    match manifest.mode {
        DeploymentMode::CertificatePki => {
            if manifest.tiers.is_empty() {
                report
                    .errors
                    .push("certificate_pki mode requires at least one tier".into());
            }
            validate_tier_chain(&manifest.tiers, &mut report);
        }
        DeploymentMode::Pkcs11Replacement => {
            if manifest.pkcs11_server.is_none() {
                report
                    .errors
                    .push("pkcs11_replacement mode requires [pkcs11_server] section".into());
            }
            if manifest.quorums.is_empty() {
                report
                    .errors
                    .push("pkcs11_replacement mode requires at least one [[quorums]] entry".into());
            }
        }
        DeploymentMode::PeerToPeer => {
            // Mode 1: minimal requirements
        }
    }

    for tier in &manifest.tiers {
        if tier.threshold.t == 0 || tier.threshold.t > tier.threshold.n {
            report.errors.push(format!(
                "tier {} has invalid threshold t={} n={}",
                tier.name, tier.threshold.t, tier.threshold.n
            ));
        }
    }

    report.valid = report.errors.is_empty();
    report
}

fn validate_tier_chain(tiers: &[crate::manifest::Tier], report: &mut ValidationReport) {
    let names: std::collections::HashSet<&str> = tiers.iter().map(|t| t.name.as_str()).collect();

    for tier in tiers {
        if let Some(parent) = &tier.delegated_by {
            if !names.contains(parent.as_str()) {
                report.errors.push(format!(
                    "tier {} delegates to unknown tier {}",
                    tier.name, parent
                ));
            }
        }
    }

    let has_root = tiers.iter().any(|t| t.delegated_by.is_none());
    if !has_root {
        report
            .errors
            .push("tier chain has no root (no tier with delegated_by absent)".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;

    fn valid_mode3_manifest() -> Manifest {
        Manifest {
            deployment: DeploymentHeader {
                name: "Test".into(),
                operator: "Op".into(),
                charter_url: None,
                manifest_version: 1,
            },
            mode: DeploymentMode::CertificatePki,
            tiers: vec![Tier {
                name: "root".into(),
                role: "root".into(),
                signing_algorithm: "FROST-ed25519".into(),
                encryption_algorithm: None,
                threshold: Threshold { t: 3, n: 5 },
                delegated_by: None,
                delegation_scope: None,
                ceremony: None,
                attributes: vec![],
            }],
            transparency: TransparencyConfig::default(),
            async_signing: AsyncSigningConfig::default(),
            archival: ArchivalConfig::default(),
            quorums: vec![],
            pkcs11_server: None,
            pqc_migration: None,
        }
    }

    #[test]
    fn valid_manifest_passes() {
        let manifest = valid_mode3_manifest();
        let report = validate_manifest(&manifest);
        assert!(report.is_ok(), "errors: {:?}", report.errors);
    }

    #[test]
    fn invalid_threshold_fails() {
        let mut manifest = valid_mode3_manifest();
        manifest.tiers[0].threshold = Threshold { t: 0, n: 5 };
        let report = validate_manifest(&manifest);
        assert!(!report.is_ok());
    }

    #[test]
    fn mode2_without_pkcs11_fails() {
        let mut manifest = valid_mode3_manifest();
        manifest.mode = DeploymentMode::Pkcs11Replacement;
        manifest.tiers.clear();
        let report = validate_manifest(&manifest);
        assert!(!report.is_ok());
    }
}
