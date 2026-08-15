//! Transparency log benches.
//!
//! Measures:
//! - `MerkleTree::root` computation at sizes 100, 1000, 10000
//! - `MerkleTree::inclusion_proof(seq)` + verify round-trip
//! - `MerkleTree::consistency_proof(old_size)` + verify round-trip

use confium_transparency::{ArtifactType, MerkleEntry, MerkleTree};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn build_tree(n: usize) -> MerkleTree {
    let mut tree = MerkleTree::new();
    // Pin the timestamp so a prefix tree built separately (e.g. the
    // old tree for consistency benchmarks) has identical leaf hashes
    // to the corresponding prefix of the larger tree.
    let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 1, 1, 0, 0, 0).unwrap();
    for i in 0..n {
        let mut entry = MerkleEntry::new(
            i as u64,
            ArtifactType::CertificateIssuance,
            [(i as u8).wrapping_mul(7); 32],
        );
        entry.timestamp = ts;
        tree.append(entry);
    }
    tree
}

fn bench_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency_root");
    group.throughput(Throughput::Elements(1));

    for size in [100usize, 1_000, 10_000] {
        let tree = build_tree(size);
        group.bench_with_input(BenchmarkId::new("root", size), &tree, |b, t| {
            b.iter(|| {
                let _ = black_box(t).root();
            })
        });
    }
    group.finish();
}

fn bench_inclusion_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency_inclusion_proof");
    group.throughput(Throughput::Elements(1));

    for size in [100usize, 1_000, 10_000] {
        let tree = build_tree(size);
        let middle_seq = (size / 2) as u64;
        let entry = tree.entry(middle_seq).unwrap().clone();
        let proof = tree.inclusion_proof(middle_seq).unwrap();
        let root = tree.root();

        group.bench_with_input(
            BenchmarkId::new("build", size),
            &(tree.clone(), middle_seq),
            |b, (t, seq)| {
                b.iter(|| {
                    let _ = black_box(t).inclusion_proof(black_box(*seq)).unwrap();
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("verify", size),
            &(entry, proof, root),
            |b, (e, p, r)| {
                b.iter(|| {
                    MerkleTree::verify_inclusion(black_box(e), black_box(p), *r).unwrap();
                })
            },
        );
    }
    group.finish();
}

fn bench_consistency_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency_consistency_proof");
    group.throughput(Throughput::Elements(1));

    for size in [100usize, 1_000, 10_000] {
        let half = size / 2;
        let tree = build_tree(size);
        // The old tree is just the first `half` entries of the same
        // deterministic sequence — its root is the expected old_root.
        let old_tree = build_tree(half);
        let old_root = old_tree.root();
        let new_root = tree.root();
        let proof = tree.consistency_proof(half).unwrap();

        group.bench_with_input(
            BenchmarkId::new("build", size),
            &(tree.clone(), half),
            |b, (t, h)| {
                b.iter(|| {
                    let _ = black_box(t).consistency_proof(black_box(*h)).unwrap();
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("verify", size),
            &(tree.clone(), old_root, new_root, half, size, proof.clone()),
            |b, (t, old_r, new_r, h, n, p)| {
                b.iter(|| {
                    black_box(t)
                        .verify_consistency(*old_r, *new_r, *h, *n, p)
                        .unwrap();
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_root,
    bench_inclusion_proof,
    bench_consistency_proof
);
criterion_main!(benches);
