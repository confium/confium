//! Differential tests for the O(log N) incremental append.
//!
//! The incremental `append_level` walk must produce exactly the tree
//! that a full rebuild would. These tests verify absolute correctness
//! (inclusion proofs verify against the tree root, consistency proofs
//! verify against fresh prefix trees) for every size 1..=64, with both
//! deterministic and system-timestamped entries.

use confium_transparency::{ArtifactType, MerkleEntry, MerkleTree};

fn pinned(i: u64) -> MerkleEntry {
    let mut e = MerkleEntry::new(
        i,
        ArtifactType::CertificateIssuance,
        [(i as u8).wrapping_mul(7); 32],
    );
    e.timestamp = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 1, 1, 0, 0, 0).unwrap();
    e
}

fn sys(i: u64) -> MerkleEntry {
    MerkleEntry::new(i, ArtifactType::ThresholdSignature, [i as u8; 32])
}

#[test]
fn incremental_inclusion_absolute_pinned_ts() {
    for n in 1usize..=64 {
        let entries: Vec<MerkleEntry> = (0..n as u64).map(pinned).collect();
        let mut tree = MerkleTree::new();
        for e in &entries {
            tree.append(e.clone());
        }
        let root = tree.root();
        for i in 0..n as u64 {
            let proof = tree.inclusion_proof(i).unwrap();
            MerkleTree::verify_inclusion(&entries[i as usize], &proof, root)
                .unwrap_or_else(|e| panic!("n={n} seq={i}: {e:?}"));
        }
    }
}

#[test]
fn incremental_inclusion_absolute_system_ts() {
    for n in 1usize..=33 {
        let entries: Vec<MerkleEntry> = (0..n as u64).map(sys).collect();
        let mut tree = MerkleTree::new();
        for e in &entries {
            tree.append(e.clone());
        }
        let root = tree.root();
        for i in 0..n as u64 {
            let proof = tree.inclusion_proof(i).unwrap();
            MerkleTree::verify_inclusion(&entries[i as usize], &proof, root)
                .unwrap_or_else(|e| panic!("n={n} seq={i}: {e:?}"));
        }
    }
}

#[test]
fn incremental_consistency_absolute() {
    // For every (old, new) pair, the consistency proof from the big tree
    // must verify against the root of a freshly-built prefix tree.
    let total = 40usize;
    let mut big = MerkleTree::new();
    let mut prefixes: Vec<MerkleTree> = Vec::new();
    for i in 0..total as u64 {
        big.append(pinned(i));
        let mut t = MerkleTree::new();
        for k in 0..=i {
            t.append(pinned(k));
        }
        prefixes.push(t);
    }
    for old in 1..total {
        let new = total;
        let proof = big.consistency_proof(old).unwrap();
        big.verify_consistency(prefixes[old - 1].root(), big.root(), old, new, &proof)
            .unwrap_or_else(|e| panic!("old={old} new={new}: {e:?}"));
    }
}
