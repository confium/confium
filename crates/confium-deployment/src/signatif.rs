//! SIGNATIF deployment manifests (SIGNATIF §18–19).
//!
//! A deployment manifest declares the whole trust topology
//! declaratively and is signed by the root trust authority whose
//! deployment it describes:
//!
//! - the topology profile (hierarchical, federated, cross-recognized,
//!   mesh) — one of the four first-class conformance profiles;
//! - every trust authority with its identifier, aggregate key or
//!   fingerprint, quorum parameters, parent references, and scope;
//! - the algorithms recognized by the deployment, from the framework's
//!   algorithm registry, plus the migration phase;
//! - the recognized transparency logs and mirrors, with the multi-log
//!   attestation policy;
//! - mutual-recognition credentials between roots (governance).
//!
//! Validation enforces: a valid trust graph with **no cycles**, the
//! monotonic scope narrowing invariant across every delegation link,
//! quorum consistency (1 <= T <= N; M <= K), and semantic versioning.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use confium_signatif::SignatifError;
use confium_signatif::SignatifResult;
use confium_signatif::graph::{Quorum, SignatureVerifier};
use confium_signatif::jcs;
use confium_signatif::scope::ScopeDimensions;

/// The four trust topology profiles (§19 `topology-declaration`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyProfile {
    /// Single root, strict delegation tree.
    Hierarchical,
    /// Threshold groups of independent organizations share aggregate
    /// keys.
    Federated,
    /// Roots attest each other via signed cross-recognition
    /// credentials.
    CrossRecognized,
    /// Many-to-many peer recognition without a distinguished root.
    Mesh,
}

impl TopologyProfile {
    /// The conformance-class identifier for this profile.
    pub fn conformance_class(&self) -> &'static str {
        match self {
            TopologyProfile::Hierarchical => "/conf/hierarchical",
            TopologyProfile::Federated => "/conf/federated",
            TopologyProfile::CrossRecognized => "/conf/cross-recognized",
            TopologyProfile::Mesh => "/conf/mesh",
        }
    }
}

/// The post-quantum migration phase (§20 `migration-declaration`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    /// Classical signatures exclusively.
    ClassicalOnly,
    /// Composite (classical AND post-quantum) for new artifacts;
    /// classical-only remain verifiable.
    Composite,
    /// Post-quantum exclusively; classical-only rejected.
    PostQuantumOnly,
}

/// One declared trust authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityDeclaration {
    /// Stable authority identifier.
    pub id: String,
    /// Aggregate (or single) public key, when carried inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate_key: Option<String>,
    /// Key fingerprint, when the key is distributed out of band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Quorum parameters; `None` for a 1-of-1 authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum: Option<Quorum>,
    /// Parent authority identifiers (empty for roots).
    #[serde(default)]
    pub parents: Vec<String>,
    /// The authority's scope.
    #[serde(default = "default_scope")]
    pub scope: ScopeDimensions,
}

fn default_scope() -> ScopeDimensions {
    ScopeDimensions::unconstrained()
}

/// One recognized transparency log or mirror.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogDeclaration {
    /// Log name.
    pub name: String,
    /// Log operator public key (verifies signed tree heads).
    pub operator_key: String,
    /// Endpoint.
    pub endpoint: String,
    /// Whether this entry is a mirror of another declared log.
    #[serde(default)]
    pub is_mirror: bool,
}

/// A mutual-recognition credential: one root attesting another
/// (§19 `mutual-recognition`), recorded in both roots' logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRecognition {
    /// The attesting root.
    pub from_root: String,
    /// The attested root.
    pub to_root: String,
    /// The attested root's aggregate key fingerprint.
    pub to_fingerprint: String,
    /// The attested root's recognized scope.
    pub recognized_scope: ScopeDimensions,
    /// The attesting root's signature over the canonical credential.
    pub signature: Vec<u8>,
}

impl CrossRecognition {
    /// Canonical signing bytes.
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn signing_bytes(&self) -> SignatifResult<Vec<u8>> {
        let v = serde_json::json!({
            "from_root": self.from_root,
            "to_root": self.to_root,
            "to_fingerprint": self.to_fingerprint,
            "recognized_scope": self.recognized_scope,
        });
        Ok(jcs::canonicalize(&v)?.into_bytes())
    }

    /// Verify the attesting root's signature over the credential
    /// (§19 `mutual-recognition`).
    ///
    /// # Errors
    ///
    /// Signature errors when the attesting root's key does not verify.
    pub fn verify(
        &self,
        from_root_key: &[u8],
        verifier: &dyn SignatureVerifier,
    ) -> SignatifResult<()> {
        let msg = self.signing_bytes()?;
        if verifier.verify(from_root_key, &msg, &self.signature) {
            Ok(())
        } else {
            Err(SignatifError::BadSignature {
                context: format!("cross-recognition {} -> {}", self.from_root, self.to_root),
            })
        }
    }
}

/// The multi-log attestation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiLogPolicyDeclaration {
    /// Required valid inclusion proofs.
    pub m: usize,
    /// Recognized independent logs.
    pub k: usize,
}

/// A root-signed declarative deployment manifest (§18).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatifManifest {
    /// Manifest version (semantic compatibility).
    pub manifest_version: u32,
    /// The deployment's topology profile.
    pub topology: TopologyProfile,
    /// All declared trust authorities (roots have empty `parents`).
    pub authorities: Vec<AuthorityDeclaration>,
    /// Algorithms recognized by this deployment (algorithm registry
    /// names).
    pub algorithms: Vec<String>,
    /// The active migration phase.
    pub migration_phase: MigrationPhase,
    /// Recognized transparency logs and mirrors.
    pub transparency_logs: Vec<LogDeclaration>,
    /// Multi-log attestation policy, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_log_policy: Option<MultiLogPolicyDeclaration>,
    /// Cross-recognition credentials between roots.
    #[serde(default)]
    pub cross_recognitions: Vec<CrossRecognition>,
    /// Manifest validity.
    pub valid_from: DateTime<Utc>,
    /// Manifest validity.
    pub valid_until: DateTime<Utc>,
    /// The root trust authority's signature over the canonical
    /// manifest body.
    pub root_signature: Vec<u8>,
}

impl SignatifManifest {
    /// Canonical signing bytes (JCS of the manifest with the signature
    /// cleared).
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn signing_bytes(&self) -> SignatifResult<Vec<u8>> {
        let mut copy = self.clone();
        copy.root_signature = Vec::new();
        Ok(
            jcs::canonicalize(&serde_json::to_value(&copy).expect("manifest serializes"))?
                .into_bytes(),
        )
    }

    /// Look up an authority declaration.
    pub fn authority(&self, id: &str) -> Option<&AuthorityDeclaration> {
        self.authorities.iter().find(|a| a.id == id)
    }

    /// The root authorities (no parents).
    pub fn roots(&self) -> Vec<&AuthorityDeclaration> {
        self.authorities
            .iter()
            .filter(|a| a.parents.is_empty())
            .collect()
    }

    /// Verify the root signature of the manifest.
    ///
    /// # Errors
    ///
    /// Signature or root-key resolution errors.
    pub fn verify_signature(&self, verifier: &dyn SignatureVerifier) -> SignatifResult<()> {
        let msg = self.signing_bytes()?;
        for root in self.roots() {
            if let Some(key_hex) = &root.aggregate_key {
                if let Ok(key) = hex::decode(key_hex) {
                    if verifier.verify(&key, &msg, &self.root_signature) {
                        return Ok(());
                    }
                }
            }
        }
        Err(SignatifError::BadSignature {
            context: "deployment manifest root signature".into(),
        })
    }

    /// Validate the whole manifest (§18 `manifest-validation-*`):
    ///
    /// 1. acyclic delegation graph;
    /// 2. monotonic scope narrowing on every parent -> child link;
    /// 3. quorum consistency (1 <= T <= N per authority, M <= K for
    ///    the multi-log policy);
    /// 4. at least one root exists.
    ///
    /// # Errors
    ///
    /// Returns the first violation as an encoding error with a
    /// precise message.
    pub fn validate(&self) -> SignatifResult<()> {
        if self.roots().is_empty() {
            return Err(SignatifError::Encoding(
                "manifest declares no root authority".into(),
            ));
        }

        // Index authorities and check parent references exist.
        let index: BTreeMap<&str, &AuthorityDeclaration> = self
            .authorities
            .iter()
            .map(|a| (a.id.as_str(), a))
            .collect();
        for a in &self.authorities {
            for p in &a.parents {
                if !index.contains_key(p.as_str()) {
                    return Err(SignatifError::Encoding(format!(
                        "authority {} references unknown parent {p}",
                        a.id
                    )));
                }
            }
        }

        // Quorum consistency (T <= N).
        for a in &self.authorities {
            if let Some(q) = a.quorum {
                Quorum::new(q.t, q.n)?;
            }
        }
        if let Some(p) = &self.multi_log_policy {
            if p.m == 0 || p.m > p.k {
                return Err(SignatifError::Encoding(format!(
                    "invalid multi-log policy {} of {}",
                    p.m, p.k
                )));
            }
        }

        // Acyclic: DFS from every authority following parents.
        // Unvisited nodes are absent from `marks` (tri-color DFS).
        #[derive(PartialEq, Clone, Copy)]
        enum Mark {
            Grey,
            Black,
        }
        fn visit(
            manifest: &SignatifManifest,
            id: &str,
            marks: &mut BTreeMap<String, Mark>,
        ) -> bool {
            match marks.get(id).copied() {
                Some(Mark::Grey) => false,
                Some(Mark::Black) => true,
                _ => {
                    marks.insert(id.to_string(), Mark::Grey);
                    if let Some(a) = manifest.authority(id) {
                        for p in &a.parents {
                            if !visit(manifest, p, marks) {
                                return false;
                            }
                        }
                    }
                    marks.insert(id.to_string(), Mark::Black);
                    true
                }
            }
        }
        let mut marks: BTreeMap<String, Mark> = BTreeMap::new();
        if !self
            .authorities
            .iter()
            .all(|a| visit(self, &a.id, &mut marks))
        {
            return Err(SignatifError::Encoding(
                "manifest trust graph contains a cycle".into(),
            ));
        }

        // Monotonic narrowing on every link.
        for a in &self.authorities {
            for p in &a.parents {
                let parent = self.authority(p).expect("checked above");
                if let Some(dim) = a.scope.first_widened_dimension(&parent.scope) {
                    return Err(SignatifError::Encoding(format!(
                        "scope widening on delegation {p} -> {} on dimension {dim}",
                        a.id
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confium_signatif::scope::ScopeValue;
    use ed25519_dalek::Signer;
    use rand_core::RngCore;

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

    fn manifest() -> (SignatifManifest, ed25519_dalek::SigningKey) {
        let root_sk = generate_key();
        let mut root_scope = ScopeDimensions::unconstrained();
        root_scope.set(
            "domain",
            ScopeValue::Set(["pharma"].iter().map(|s| s.to_string()).collect()),
        );
        let mut lab_scope = root_scope.clone();
        lab_scope.set("subdomain", ScopeValue::Single("vaccines".into()));

        let m = SignatifManifest {
            manifest_version: 1,
            topology: TopologyProfile::Hierarchical,
            authorities: vec![
                AuthorityDeclaration {
                    id: "root".into(),
                    aggregate_key: Some(hex::encode(root_sk.verifying_key().as_bytes())),
                    fingerprint: Some("f0".into()),
                    quorum: Some(Quorum { t: 2, n: 3 }),
                    parents: vec![],
                    scope: root_scope,
                },
                AuthorityDeclaration {
                    id: "lab".into(),
                    aggregate_key: None,
                    fingerprint: Some("f1".into()),
                    quorum: Some(Quorum { t: 2, n: 3 }),
                    parents: vec!["root".into()],
                    scope: lab_scope,
                },
            ],
            algorithms: vec!["Ed25519".into(), "ECDSA-P256".into()],
            migration_phase: MigrationPhase::ClassicalOnly,
            transparency_logs: vec![LogDeclaration {
                name: "log-1".into(),
                operator_key: "00".into(),
                endpoint: "https://log.example".into(),
                is_mirror: false,
            }],
            multi_log_policy: Some(MultiLogPolicyDeclaration { m: 1, k: 1 }),
            cross_recognitions: vec![],
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::days(365),
            root_signature: vec![],
        };
        (m, root_sk)
    }

    #[test]
    fn valid_manifest_validates_and_signs() {
        let (mut m, sk) = manifest();
        m.root_signature = sk.sign(&m.signing_bytes().unwrap()).to_bytes().to_vec();
        assert!(m.validate().is_ok());
        assert!(m.verify_signature(&Ed25519Verifier).is_ok());
        assert_eq!(m.roots().len(), 1);
    }

    #[test]
    fn cycle_is_rejected() {
        let (mut m, _) = manifest();
        let lab = m.authorities[1].clone();
        m.authorities.push(AuthorityDeclaration {
            id: "mid".into(),
            aggregate_key: None,
            fingerprint: Some("f2".into()),
            quorum: None,
            parents: vec!["lab".into()],
            scope: lab.scope.clone(),
        });
        // lab -> mid -> lab cycle (root stays parentless).
        m.authorities[1].parents = vec!["root".into(), "mid".into()];
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("cycle"), "got {err}");
    }

    #[test]
    fn widening_is_rejected() {
        let (mut m, _) = manifest();
        m.authorities[1].scope = ScopeDimensions::unconstrained();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("widening"));
    }

    #[test]
    fn quorum_and_multilog_consistency() {
        let (mut m, _) = manifest();
        m.authorities[1].quorum = Some(Quorum { t: 4, n: 3 });
        assert!(m.validate().is_err());
        m.authorities[1].quorum = None;
        m.multi_log_policy = Some(MultiLogPolicyDeclaration { m: 3, k: 2 });
        assert!(m.validate().is_err());
    }

    #[test]
    fn no_roots_rejected() {
        let (mut m, _) = manifest();
        m.authorities[0].parents = vec!["lab".into()];
        m.authorities[1].parents = vec!["root".into()];
        assert!(m.validate().is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let (mut m, sk) = manifest();
        m.root_signature = sk.sign(&m.signing_bytes().unwrap()).to_bytes().to_vec();
        m.algorithms.push("ML-DSA-65".into());
        assert!(m.verify_signature(&Ed25519Verifier).is_err());
    }

    #[test]
    fn cross_recognition_signature_verifies() {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let root_a = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut cred = CrossRecognition {
            from_root: "root-a".into(),
            to_root: "root-b".into(),
            to_fingerprint: "fbb".into(),
            recognized_scope: ScopeDimensions::unconstrained(),
            signature: vec![],
        };
        cred.signature = root_a
            .sign(&cred.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        assert!(
            cred.verify(root_a.verifying_key().as_bytes(), &Ed25519Verifier)
                .is_ok()
        );
        cred.to_root = "root-c".into();
        assert!(
            cred.verify(root_a.verifying_key().as_bytes(), &Ed25519Verifier)
                .is_err()
        );
    }

    #[test]
    fn topology_conformance_classes() {
        assert_eq!(
            TopologyProfile::Hierarchical.conformance_class(),
            "/conf/hierarchical"
        );
        assert_eq!(TopologyProfile::Mesh.conformance_class(), "/conf/mesh");
    }
}
