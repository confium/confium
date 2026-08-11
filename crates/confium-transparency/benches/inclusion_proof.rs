//! Benchmark: MerkleTree inclusion_proof at various tree sizes.
//!
//! Demonstrates the O(log N) scaling of `inclusion_proof` after
//! the cached-levels optimization. Compare with the previous O(N)
//! behavior by reverting the rebuild_levels change.

use criterion::{BenchmarkId, criterion_group, criterion_main, Criterion};
use confium_transparency::entry::{ArtifactType, MerkleEntry};
use confium_transparency::merkle::MerkleTree;

fn build_tree(n: u64) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for i in 0..n {
        let hash = [(i as u8).wrapping_mul(7); 32];
        let entry = MerkleEntry::new(i, ArtifactType::CertificateIssuance, hash);
        tree.append(entry);
    }
    tree
}

fn bench_inclusion_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("inclusion_proof");
    for size in [64u64, 256, 1024, 4096, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let tree = build_tree(size);
            // Mid-tree leaf — exercises both halves of the tree.
            let seq = size / 2;
            b.iter(|| {
                let _ = tree.inclusion_proof(seq).expect("proof");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_inclusion_proof);
criterion_main!(benches);
