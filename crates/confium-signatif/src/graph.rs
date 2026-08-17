//! The trust graph: delegation DAG and verification path-finding
//! (SIGNATIF §7).
//!
//! Nodes are trust authorities (root, delegated, or end-certificate)
//! carrying an aggregate public key, optional quorum parameters, and a
//! multi-dimensional scope. Edges are delegation credentials — the
//! parent's signature over the child's binding (identifier, key,
//! quorum, scope). The graph generalizes a linear chain to a directed
//! acyclic graph: cross-recognition and federated memberships produce
//! multiple parents.
//!
//! [`TrustGraph::find_paths`] collects **every** path from an artifact
//! signer to a root present in the trust anchor bundle, validating the
//! delegation signature and the monotonic scope narrowing at each link.
//! Multiple valid paths and multiple distinct roots feed the coverage
//! report's cross-domain diversity scoring.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bundle::TrustAnchorBundle;
use crate::error::{SignatifError, SignatifResult};
use crate::jcs;
use crate::scope::ScopeDimensions;

/// Threshold quorum parameters (T of N).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quorum {
    /// Threshold — signatures required.
    pub t: u32,
    /// Committee size.
    pub n: u32,
}

impl Quorum {
    /// Construct a quorum, validating T <= N and T >= 1.
    ///
    /// # Errors
    ///
    /// Returns [`SignatifError::Encoding`] when the parameters are
    /// inconsistent.
    pub fn new(t: u32, n: u32) -> SignatifResult<Self> {
        if t == 0 || t > n {
            return Err(SignatifError::Encoding(format!(
                "invalid quorum {t} of {n}: require 1 <= T <= N"
            )));
        }
        Ok(Self { t, n })
    }
}

/// The kind of a trust authority node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    /// A root trust authority — verification terminus.
    Root,
    /// A delegated trust authority.
    Delegated,
    /// An end certificate authorizing one signing key.
    EndCertificate,
}

/// A node in the trust graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityNode {
    /// Stable identifier (typically a key fingerprint).
    pub id: String,
    /// Kind of authority.
    pub kind: AuthorityKind,
    /// Aggregate (or single) public key, SPKI-encoded.
    pub public_key: Vec<u8>,
    /// Quorum parameters when the authority is threshold.
    pub quorum: Option<Quorum>,
    /// The authority's authorization scope.
    pub scope: ScopeDimensions,
}

impl AuthorityNode {
    /// The canonical signing input for this node's binding: the JCS of
    /// the node's identity material. Delegation signatures and anchor
    /// bundle references are computed over these bytes.
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn binding_bytes(&self) -> SignatifResult<Vec<u8>> {
        let v = serde_json::json!({
            "id": self.id,
            "kind": self.kind,
            "public_key": hex::encode(&self.public_key),
            "quorum": self.quorum,
            "scope": self.scope,
        });
        Ok(jcs::canonicalize(&v)?.into_bytes())
    }
}

/// A delegation edge: the parent's credential over the child node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEdge {
    /// Parent authority identifier.
    pub parent: String,
    /// Child authority identifier.
    pub child: String,
    /// The parent's signature over the child's [`AuthorityNode::binding_bytes`].
    pub signature: Vec<u8>,
}

/// One verified delegation link on a path.
#[derive(Debug, Clone)]
pub struct PathLink {
    /// The parent authority.
    pub parent: AuthorityNode,
    /// The child authority.
    pub child: AuthorityNode,
    /// The delegation credential that was verified.
    pub edge: DelegationEdge,
}

/// A complete verification path from an artifact signer to a root.
#[derive(Debug, Clone)]
pub struct VerificationPath {
    /// Links in order from the signer's node up to (excluding) the root.
    pub links: Vec<PathLink>,
    /// The root authority terminating the path.
    pub root: AuthorityNode,
}

impl VerificationPath {
    /// The distinct authorities on this path, signer first.
    pub fn authorities(&self) -> Vec<&AuthorityNode> {
        let mut out = Vec::new();
        if let Some(first) = self.links.first() {
            out.push(&first.child);
        }
        for link in &self.links {
            out.push(&link.parent);
        }
        out.push(&self.root);
        out
    }

    /// The scope of the signer node (the most-narrow scope on the path).
    pub fn signer_scope(&self) -> &ScopeDimensions {
        self.links
            .first()
            .map(|l| &l.child.scope)
            .unwrap_or(&self.root.scope)
    }
}

/// Verifies a delegation signature: `signature` over `message` under
/// `public_key`. Implementations bind the concrete algorithm fleet
/// (Ed25519, ECDSA-P256, ML-DSA, threshold aggregate verification).
pub trait SignatureVerifier {
    /// Verify `signature` over `message` under `public_key`.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// A no-op verifier that accepts everything — for graph topology tests
/// only; never use in production code paths.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllVerifier;

impl SignatureVerifier for AcceptAllVerifier {
    fn verify(&self, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
        true
    }
}

/// The trust graph: authorities and delegation edges forming a DAG.
#[derive(Debug, Clone, Default)]
pub struct TrustGraph {
    nodes: BTreeMap<String, AuthorityNode>,
    edges: Vec<DelegationEdge>,
}

impl TrustGraph {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a node, replacing any node with the same identifier.
    pub fn add_node(&mut self, node: AuthorityNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Insert a delegation edge. Returns an error when either endpoint
    /// is unknown or when the edge would create a cycle.
    ///
    /// # Errors
    ///
    /// [`SignatifError::Encoding`] for unknown endpoints or a cycle.
    pub fn add_delegation(&mut self, edge: DelegationEdge) -> SignatifResult<()> {
        if !self.nodes.contains_key(&edge.parent) || !self.nodes.contains_key(&edge.child) {
            return Err(SignatifError::Encoding(format!(
                "delegation references unknown node(s) {} -> {}",
                edge.parent, edge.child
            )));
        }
        self.edges.push(edge);
        if !self.is_acyclic() {
            self.edges.pop();
            return Err(SignatifError::Encoding(
                "delegation would create a cycle in the trust graph".into(),
            ));
        }
        Ok(())
    }

    /// All nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &AuthorityNode> {
        self.nodes.values()
    }

    /// All delegation edges.
    pub fn edges(&self) -> &[DelegationEdge] {
        &self.edges
    }

    /// Look up a node by identifier.
    pub fn node(&self, id: &str) -> Option<&AuthorityNode> {
        self.nodes.get(id)
    }

    /// Incoming delegation edges for a child node.
    pub fn parents_of(&self, child: &str) -> Vec<&DelegationEdge> {
        self.edges.iter().filter(|e| e.child == child).collect()
    }

    /// Cycle detection over the delegation graph.
    pub fn is_acyclic(&self) -> bool {
        #[derive(Clone, Copy, PartialEq)]
        enum Mark {
            #[allow(dead_code)]
            White,
            Grey,
            Black,
        }
        fn visit(graph: &TrustGraph, id: &str, marks: &mut BTreeMap<String, Mark>) -> bool {
            match marks.get(id).copied() {
                Some(Mark::Grey) => false,
                Some(Mark::Black) => true,
                _ => {
                    marks.insert(id.to_string(), Mark::Grey);
                    for edge in graph.parents_of(id) {
                        if !visit(graph, &edge.parent, marks) {
                            return false;
                        }
                    }
                    marks.insert(id.to_string(), Mark::Black);
                    true
                }
            }
        }
        let mut marks: BTreeMap<String, Mark> = BTreeMap::new();
        self.nodes.keys().all(|id| visit(self, id, &mut marks))
    }

    /// Find **all** verification paths from `signer` to roots present in
    /// `bundle`. Each link is validated: the parent's delegation
    /// signature over the child's binding bytes, the monotonic scope
    /// narrowing invariant, and — for the terminal link — that the root
    /// matches an anchor in the bundle by aggregate key.
    ///
    /// # Errors
    ///
    /// Returns [`SignatifError::ScopeWidening`] on the first widening
    /// link (a hard failure), and [`SignatifError::BadSignature`] when
    /// a delegation credential does not verify.
    pub fn find_paths(
        &self,
        signer: &str,
        bundle: &TrustAnchorBundle,
        verifier: &dyn SignatureVerifier,
    ) -> SignatifResult<Vec<VerificationPath>> {
        let signer_node = self.nodes.get(signer).ok_or(SignatifError::NoPath)?;
        let mut paths = Vec::new();
        let mut prefix: Vec<PathLink> = Vec::new();
        self.walk(signer_node, bundle, verifier, &mut prefix, &mut paths)?;
        Ok(paths)
    }

    fn walk(
        &self,
        node: &AuthorityNode,
        bundle: &TrustAnchorBundle,
        verifier: &dyn SignatureVerifier,
        prefix: &mut Vec<PathLink>,
        out: &mut Vec<VerificationPath>,
    ) -> SignatifResult<()> {
        if node.kind == AuthorityKind::Root {
            if bundle.matches_root(&node.public_key) {
                out.push(VerificationPath {
                    links: prefix.clone(),
                    root: node.clone(),
                });
            }
            return Ok(());
        }
        for edge in self.parents_of(&node.id) {
            let parent = match self.nodes.get(&edge.parent) {
                Some(p) => p,
                None => continue,
            };
            if !verifier.verify(&parent.public_key, &node.binding_bytes()?, &edge.signature) {
                return Err(SignatifError::BadSignature {
                    context: format!("delegation {} -> {}", edge.parent, node.id),
                });
            }
            if let Some(dim) = node.scope.first_widened_dimension(&parent.scope) {
                return Err(SignatifError::ScopeWidening {
                    parent: parent.id.clone(),
                    child: node.id.clone(),
                    dimension: dim,
                });
            }
            prefix.push(PathLink {
                parent: parent.clone(),
                child: node.clone(),
                edge: edge.clone(),
            });
            self.walk(parent, bundle, verifier, prefix, out)?;
            prefix.pop();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::AnchorRoot;
    use crate::scope::ScopeValue;
    use chrono::{Duration, Utc};
    use sha2::Digest as _;

    fn generate_key() -> ed25519_dalek::SigningKey {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    fn ed25519_keypair() -> (ed25519_dalek::SigningKey, Vec<u8>) {
        let sk = generate_key();
        let pk = sk.verifying_key().as_bytes().to_vec();
        (sk, pk)
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

    fn root(id: &str, scope: ScopeDimensions) -> (AuthorityNode, ed25519_dalek::SigningKey) {
        let (sk, pk) = ed25519_keypair();
        (
            AuthorityNode {
                id: id.into(),
                kind: AuthorityKind::Root,
                public_key: pk,
                quorum: None,
                scope,
            },
            sk,
        )
    }

    fn child(
        id: &str,
        kind: AuthorityKind,
        scope: ScopeDimensions,
        key: &ed25519_dalek::SigningKey,
    ) -> AuthorityNode {
        AuthorityNode {
            id: id.into(),
            kind,
            public_key: key.verifying_key().as_bytes().to_vec(),
            quorum: Some(Quorum::new(2, 3).unwrap()),
            scope,
        }
    }

    fn sign(sk: &ed25519_dalek::SigningKey, node: &AuthorityNode) -> Vec<u8> {
        use ed25519_dalek::Signer;
        sk.sign(&node.binding_bytes().unwrap()).to_bytes().to_vec()
    }

    fn bundle_for(root_node: &AuthorityNode) -> TrustAnchorBundle {
        TrustAnchorBundle {
            bundle_version: "2026.08".into(),
            valid_from: Utc::now() - Duration::hours(1),
            valid_until: Utc::now() + Duration::days(365),
            roots: vec![AnchorRoot {
                name: root_node.id.clone(),
                aggregate_key: root_node.public_key.clone(),
                fingerprint: hex::encode(sha2::Sha256::digest(&root_node.public_key)),
                quorum: root_node.quorum,
            }],
            transparency_logs: Vec::new(),
            bundle_signature: Vec::new(),
        }
    }

    #[test]
    fn finds_single_path_and_validates_links() {
        let mut parent_scope = ScopeDimensions::unconstrained();
        parent_scope.set("domain", ScopeValue::Wildcard);
        let (root_node, root_sk) = root("root-1", parent_scope);

        let mut child_scope = ScopeDimensions::unconstrained();
        child_scope.set("domain", ScopeValue::Single("pharma".into()));
        let (end_sk, _) = ed25519_keypair();
        let end = child("end-1", AuthorityKind::EndCertificate, child_scope, &end_sk);

        let mut graph = TrustGraph::new();
        graph.add_node(root_node.clone());
        graph.add_node(end.clone());
        graph
            .add_delegation(DelegationEdge {
                parent: "root-1".into(),
                child: "end-1".into(),
                signature: sign(&root_sk, &end),
            })
            .unwrap();

        let bundle = bundle_for(&root_node);
        let paths = graph
            .find_paths("end-1", &bundle, &Ed25519Verifier)
            .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].root.id, "root-1");
        assert_eq!(paths[0].links.len(), 1);
    }

    #[test]
    fn tampered_delegation_signature_is_hard_failure() {
        let (root_node, root_sk) = root("root-1", ScopeDimensions::unconstrained());
        let (end_sk, _) = ed25519_keypair();
        let end = child(
            "end-1",
            AuthorityKind::EndCertificate,
            ScopeDimensions::unconstrained(),
            &end_sk,
        );
        let mut bad = sign(&root_sk, &end);
        bad[0] ^= 1;
        let mut graph = TrustGraph::new();
        graph.add_node(root_node.clone());
        graph.add_node(end);
        graph
            .add_delegation(DelegationEdge {
                parent: "root-1".into(),
                child: "end-1".into(),
                signature: bad,
            })
            .unwrap();
        let err = graph
            .find_paths("end-1", &bundle_for(&root_node), &Ed25519Verifier)
            .unwrap_err();
        assert!(matches!(err, SignatifError::BadSignature { .. }));
    }

    #[test]
    fn scope_widening_is_hard_failure() {
        let mut narrow = ScopeDimensions::unconstrained();
        narrow.set("domain", ScopeValue::Single("pharma".into()));
        let mut wide = ScopeDimensions::unconstrained();
        wide.set(
            "domain",
            ScopeValue::Set(["pharma", "food"].iter().map(|s| s.to_string()).collect()),
        );
        let (root_node, root_sk) = root("root-1", narrow);
        let (end_sk, _) = ed25519_keypair();
        let end = child("end-1", AuthorityKind::EndCertificate, wide, &end_sk);
        let mut graph = TrustGraph::new();
        graph.add_node(root_node.clone());
        let edge_sig = sign(&root_sk, &end);
        graph.add_node(end);
        graph
            .add_delegation(DelegationEdge {
                parent: "root-1".into(),
                child: "end-1".into(),
                signature: edge_sig,
            })
            .unwrap();
        let err = graph
            .find_paths("end-1", &bundle_for(&root_node), &Ed25519Verifier)
            .unwrap_err();
        match err {
            SignatifError::ScopeWidening { dimension, .. } => assert_eq!(dimension, "domain"),
            other => panic!("expected widening, got {other:?}"),
        }
    }

    #[test]
    fn multiple_roots_yield_multiple_paths() {
        let (r1, s1) = root("root-1", ScopeDimensions::unconstrained());
        let (r2, s2) = root("root-2", ScopeDimensions::unconstrained());
        let (end_sk, _) = ed25519_keypair();
        let end = child(
            "end-1",
            AuthorityKind::EndCertificate,
            ScopeDimensions::unconstrained(),
            &end_sk,
        );
        let mut graph = TrustGraph::new();
        graph.add_node(r1.clone());
        graph.add_node(r2.clone());
        graph.add_node(end.clone());
        for (parent, sk) in [("root-1", &s1), ("root-2", &s2)] {
            graph
                .add_delegation(DelegationEdge {
                    parent: parent.into(),
                    child: "end-1".into(),
                    signature: sign(sk, &end),
                })
                .unwrap();
        }
        let mut bundle = bundle_for(&r1);
        bundle.roots.push(AnchorRoot {
            name: "root-2".into(),
            aggregate_key: r2.public_key.clone(),
            fingerprint: hex::encode(sha2::Sha256::digest(&r2.public_key)),
            quorum: None,
        });
        let paths = graph
            .find_paths("end-1", &bundle, &Ed25519Verifier)
            .unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn cycles_are_rejected_at_insertion() {
        let (r, _) = root("root-1", ScopeDimensions::unconstrained());
        let (a_sk, _) = ed25519_keypair();
        let a = child(
            "a",
            AuthorityKind::Delegated,
            ScopeDimensions::unconstrained(),
            &a_sk,
        );
        let mut graph = TrustGraph::new();
        graph.add_node(r);
        graph.add_node(a.clone());
        graph
            .add_delegation(DelegationEdge {
                parent: "root-1".into(),
                child: "a".into(),
                signature: vec![0],
            })
            .unwrap();
        assert!(
            graph
                .add_delegation(DelegationEdge {
                    parent: "a".into(),
                    child: "root-1".into(),
                    signature: vec![0],
                })
                .is_err()
        );
        assert!(graph.is_acyclic());
    }
}
