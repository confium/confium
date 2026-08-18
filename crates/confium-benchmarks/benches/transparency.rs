//! Transparency log benches.
//!
//! Measures:
//! - `MerkleTree::append` (incremental O(log N) path) at tree sizes
//!   100, 1000, 10000
//! - `MerkleTree::root` computation at sizes 100, 1000, 10000
//! - `MerkleTree::inclusion_proof(seq)` + verify round-trip
//! - `MerkleTree::consistency_proof(old_size)` + verify round-trip

use confium_transparency::{ArtifactType, MerkleEntry, MerkleTree};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn pinned_entry(i: u64, ts: chrono::DateTime<chrono::Utc>) -> MerkleEntry {
    let mut entry = MerkleEntry::new(
        i,
        ArtifactType::CertificateIssuance,
        [(i as u8).wrapping_mul(7); 32],
    );
    entry.timestamp = ts;
    entry
}

fn build_tree(n: usize) -> MerkleTree {
    let mut tree = MerkleTree::new();
    // Pin the timestamp so a prefix tree built separately (e.g. the
    // old tree for consistency benchmarks) has identical leaf hashes
    // to the corresponding prefix of the larger tree.
    let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 1, 1, 0, 0, 0).unwrap();
    for i in 0..n {
        tree.append(pinned_entry(i as u64, ts));
    }
    tree
}

fn bench_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency_append");
    // Throughput is leaves appended per iteration.
    group.throughput(Throughput::Elements(1));

    for size in [100usize, 1_000, 10_000] {
        // Pre-build to `size`, then measure appending the NEXT leaf —
        // the incremental path's cost at that tree size.
        let mut tree = build_tree(size);
        let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 1, 1, 0, 0, 0).unwrap();
        let seq = std::cell::Cell::new(size as u64);
        group.bench_with_input(BenchmarkId::new("next_leaf", size), &(), |b, _| {
            b.iter_batched(
                || pinned_entry(seq.get(), ts),
                |entry| {
                    let t = black_box(&mut tree);
                    t.append(entry);
                    // Advance so each appended leaf is unique.
                    seq.set(seq.get() + 1);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
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
    bench_append,
    bench_root,
    bench_inclusion_proof,
    bench_consistency_proof
);
criterion_main!(benches);
