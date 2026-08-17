//! Multi-log attestation and gossip quorum (SIGNATIF §13).
//!
//! - [`MultiLogPolicy`] `{m, k}`: a federated authority's artifacts
//!   must carry inclusion proofs from at least M of K independent
//!   logs — no single log operator controls the record.
//! - [`GossipQuorum`]: the signed tree head a verifier relies on must
//!   be witnessed by at least N independent witnesses.
//! - [`MultiLogAttestation`]: the verification side — which logs
//!   produced valid inclusion proofs.

use serde::{Deserialize, Serialize};

/// M-of-K multi-log policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiLogPolicy {
    /// Required number of valid inclusion proofs.
    pub m: usize,
    /// Recognized independent logs.
    pub k: usize,
}

impl MultiLogPolicy {
    /// Validate M <= K and M >= 1.
    ///
    /// # Errors
    ///
    /// Returns an encoding error for inconsistent parameters.
    pub fn validate(&self) -> crate::error::SignatifResult<()> {
        if self.m == 0 || self.m > self.k {
            return Err(crate::error::SignatifError::Encoding(format!(
                "invalid multi-log policy {} of {}",
                self.m, self.k
            )));
        }
        Ok(())
    }
}

/// One log's inclusion-verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogInclusion {
    /// Log name.
    pub log: String,
    /// Whether a valid inclusion proof was verified for the artifact.
    pub included: bool,
}

/// The set of inclusion results evaluated against a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiLogAttestation {
    /// Per-log results.
    pub inclusions: Vec<LogInclusion>,
}

impl MultiLogAttestation {
    /// Evaluate the M-of-K quorum.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy parameters are inconsistent.
    pub fn satisfies(&self, policy: &MultiLogPolicy) -> crate::error::SignatifResult<bool> {
        policy.validate()?;
        let included = self.inclusions.iter().filter(|i| i.included).count();
        Ok(included >= policy.m)
    }
}

/// One witness's signature over a signed tree head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessCosignature {
    /// Witness identity.
    pub witness: String,
    /// The witnessed tree head bytes (root hash + size + timestamp).
    pub tree_head_bytes: Vec<u8>,
    /// The witness's signature over the tree head bytes.
    pub signature: Vec<u8>,
    /// The witness's public key.
    pub public_key: Vec<u8>,
}

/// Gossip quorum verification: at least `min_sources` distinct,
/// independently-signed observations of the *same* tree head.
#[derive(Debug, Clone, Copy)]
pub struct GossipQuorum {
    /// Minimum independent witnesses required.
    pub min_sources: usize,
}

impl GossipQuorum {
    /// Check the quorum.
    ///
    /// # Errors
    ///
    /// Propagates signature-verification errors as hard failures.
    pub fn check(
        &self,
        cosignatures: &[WitnessCosignature],
        verifier: &dyn crate::graph::SignatureVerifier,
    ) -> crate::error::SignatifResult<bool> {
        use std::collections::BTreeMap;
        // Group by tree head bytes; a quorum must agree on one head.
        let mut by_head: BTreeMap<Vec<u8>, Vec<&WitnessCosignature>> = BTreeMap::new();
        for c in cosignatures {
            by_head
                .entry(c.tree_head_bytes.clone())
                .or_default()
                .push(c);
        }
        for (_, witnesses) in by_head {
            let mut distinct = std::collections::BTreeSet::new();
            let mut all_valid = true;
            for w in &witnesses {
                if !verifier.verify(&w.public_key, &w.tree_head_bytes, &w.signature) {
                    all_valid = false;
                    break;
                }
                distinct.insert(w.witness.clone());
            }
            if all_valid && distinct.len() >= self.min_sources {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn generate_key() -> ed25519_dalek::SigningKey {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    struct Ed25519Verifier;

    impl crate::graph::SignatureVerifier for Ed25519Verifier {
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

    #[test]
    fn multilog_quorum() {
        let policy = MultiLogPolicy { m: 2, k: 3 };
        let att = MultiLogAttestation {
            inclusions: vec![
                LogInclusion {
                    log: "a".into(),
                    included: true,
                },
                LogInclusion {
                    log: "b".into(),
                    included: true,
                },
                LogInclusion {
                    log: "c".into(),
                    included: false,
                },
            ],
        };
        assert!(att.satisfies(&policy).unwrap());
        let weak = MultiLogAttestation {
            inclusions: vec![
                LogInclusion {
                    log: "a".into(),
                    included: true,
                },
                LogInclusion {
                    log: "b".into(),
                    included: false,
                },
                LogInclusion {
                    log: "c".into(),
                    included: false,
                },
            ],
        };
        assert!(!weak.satisfies(&policy).unwrap());
        assert!(policy.with_m_zero().validate().is_err());
    }

    impl MultiLogPolicy {
        fn with_m_zero(&self) -> MultiLogPolicy {
            MultiLogPolicy { m: 0, k: self.k }
        }
    }

    #[test]
    fn gossip_quorum_needs_agreement() {
        let head = b"tree-head-v1".to_vec();
        let witnesses: Vec<SigningKey> = (0..3).map(|_| generate_key()).collect();
        let cosigns: Vec<WitnessCosignature> = witnesses
            .iter()
            .enumerate()
            .map(|(i, sk)| WitnessCosignature {
                witness: format!("w{i}"),
                tree_head_bytes: head.clone(),
                signature: sk.sign(&head).to_bytes().to_vec(),
                public_key: sk.verifying_key().as_bytes().to_vec(),
            })
            .collect();
        let q = GossipQuorum { min_sources: 3 };
        assert!(q.check(&cosigns, &Ed25519Verifier).unwrap());

        // Split view: two heads, no single head has the quorum.
        let mut split = cosigns.clone();
        split[2].tree_head_bytes = b"other-head".to_vec();
        assert!(!q.check(&split, &Ed25519Verifier).unwrap());

        // Forged signature invalidates that head's group.
        let mut forged = cosigns.clone();
        forged[1].signature[0] ^= 1;
        assert!(!q.check(&forged, &Ed25519Verifier).unwrap());
    }
}
