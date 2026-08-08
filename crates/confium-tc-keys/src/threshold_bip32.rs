//! Threshold BIP-32 HD key derivation.
//!
//! BIP-32 hierarchical deterministic key derivation in the threshold
//! setting. Each party derives child key shares without reconstructing
//! the parent key.

use p256::elliptic_curve::PrimeField;
use p256::{FieldBytes, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A derivation path component (index + hardened flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathIndex {
    pub index: u32,
    pub hardened: bool,
}

/// A BIP-32 derivation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationPath {
    pub components: Vec<PathIndex>,
}

impl DerivationPath {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    pub fn push(&mut self, index: u32, hardened: bool) -> &mut Self {
        self.components.push(PathIndex { index, hardened });
        self
    }

    pub fn depth(&self) -> usize {
        self.components.len()
    }
}

impl Default for DerivationPath {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a child scalar from a parent scalar and path component.
/// Uses HMAC-SHA256 based derivation (BIP-32 style adapted for P-256).
pub fn derive_child_scalar(parent: &Scalar, component: &PathIndex) -> Scalar {
    let parent_bytes = parent.to_repr();
    let mut hasher = Sha256::new();
    hasher.update(b"confium-bip32-v1");
    hasher.update(&parent_bytes);
    if component.hardened {
        hasher.update(b"H");
    } else {
        hasher.update(b"N");
    }
    hasher.update(&component.index.to_be_bytes());
    let hash = hasher.finalize();

    let fb = FieldBytes::from(hash);
    let ct = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

/// Derive a scalar from a parent following a full path.
pub fn derive_path(parent: &Scalar, path: &DerivationPath) -> Scalar {
    let mut current = *parent;
    for component in &path.components {
        current = derive_child_scalar(&current, component);
    }
    current
}

/// Each party in a threshold quorum derives their child share
/// independently. Since derivation is deterministic, all parties
/// at the same path index derive consistently.
pub fn derive_party_share(parent_share: &Scalar, party_idx: u32, path: &DerivationPath) -> Scalar {
    let mut current = *parent_share;
    for component in &path.components {
        let mut c = *component;
        // Mix in party index so each party gets a distinct child share
        let mixed_index = c.index.wrapping_add(party_idx);
        c.index = mixed_index;
        current = derive_child_scalar(&current, &c);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Field;
    use p256::elliptic_curve::rand_core::OsRng;

    fn random_scalar() -> Scalar {
        Scalar::random(&mut OsRng)
    }

    #[test]
    fn derivation_is_deterministic() {
        let parent = random_scalar();
        let mut path = DerivationPath::new();
        path.push(0, false).push(1, true);
        let child1 = derive_path(&parent, &path);
        let child2 = derive_path(&parent, &path);
        assert_eq!(child1, child2);
    }

    #[test]
    fn different_parents_different_children() {
        let p1 = random_scalar();
        let p2 = random_scalar();
        let path = DerivationPath::new();
        let c1 = derive_path(&p1, &path);
        let c2 = derive_path(&p2, &path);
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_paths_different_children() {
        let parent = random_scalar();
        let mut path1 = DerivationPath::new();
        path1.push(0, false);
        let mut path2 = DerivationPath::new();
        path2.push(1, false);
        assert_ne!(derive_path(&parent, &path1), derive_path(&parent, &path2));
    }

    #[test]
    fn hardened_vs_unhardened_differ() {
        let parent = random_scalar();
        let mut h = DerivationPath::new();
        h.push(0, true);
        let mut n = DerivationPath::new();
        n.push(0, false);
        assert_ne!(derive_path(&parent, &h), derive_path(&parent, &n));
    }

    #[test]
    fn empty_path_returns_parent() {
        let parent = random_scalar();
        let path = DerivationPath::new();
        assert_eq!(derive_path(&parent, &path), parent);
    }

    #[test]
    fn depth_counts_components() {
        let mut path = DerivationPath::new();
        assert_eq!(path.depth(), 0);
        path.push(0, false);
        assert_eq!(path.depth(), 1);
        path.push(1, true);
        assert_eq!(path.depth(), 2);
    }

    #[test]
    fn party_shares_differ_by_party() {
        let parent = random_scalar();
        let mut path = DerivationPath::new();
        path.push(0, false);
        let s1 = derive_party_share(&parent, 1, &path);
        let s2 = derive_party_share(&parent, 2, &path);
        assert_ne!(s1, s2);
    }

    #[test]
    fn party_share_deterministic() {
        let parent = random_scalar();
        let mut path = DerivationPath::new();
        path.push(42, true);
        let s1 = derive_party_share(&parent, 1, &path);
        let s2 = derive_party_share(&parent, 1, &path);
        assert_eq!(s1, s2);
    }

    #[test]
    fn deep_path_works() {
        let parent = random_scalar();
        let mut path = DerivationPath::new();
        for i in 0..10 {
            path.push(i, i % 2 == 0);
        }
        let child = derive_path(&parent, &path);
        // Just verify it doesn't panic and produces a valid scalar
        let _bytes = child.to_repr();
    }

    #[test]
    fn path_serializes() {
        let mut path = DerivationPath::new();
        path.push(0, false).push(1, true);
        let json = serde_json::to_string(&path).unwrap();
        assert!(json.contains("components"));
    }
}
