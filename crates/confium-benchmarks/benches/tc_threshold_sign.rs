//! Threshold-ECDSA benchmarks for CMP20, GG18, and FROST-P256.
//!
//! Each protocol is benched across two sweeps:
//!
//! - **Threshold sweep** (party_count fixed at 5, threshold varies 2..=5)
//! - **Party-count sweep** (threshold fixed at 3, party_count varies 3..=9)
//!
//! The reported numbers cover DKG + sign + verify for one full cycle.
//! Verify cost is independent of the threshold protocol and serves as
//! a baseline (it's the same `p256::ecdsa::VerifyingKey::verify` call
//! across all three protocols).

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

fn bench_dkg_and_sign_threshold_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("tc_threshold_sweep");

    // Threshold sweep: party_count fixed at 5.
    let party_count = 5usize;
    for threshold in [2u32, 3, 4, 5] {
        group.bench_with_input(
            BenchmarkId::new("cmp20", format!("t={threshold}_n={party_count}")),
            &(threshold, party_count),
            |b, &(t, n)| {
                b.iter(|| {
                    let kg = confium_tc_cmp20::inprocess::keygen(t, n).unwrap();
                    confium_tc_cmp20::inprocess::sign(&kg.shares[..t as usize], t, b"bench")
                        .unwrap()
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("gg18", format!("t={threshold}_n={party_count}")),
            &(threshold, party_count),
            |b, &(t, n)| {
                b.iter(|| {
                    let kg = confium_tc_gg18::inprocess::keygen(t, n).unwrap();
                    confium_tc_gg18::inprocess::sign(&kg.shares[..t as usize], t, b"bench").unwrap()
                });
            },
        );
    }

    group.finish();
}

fn bench_dkg_and_sign_party_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("tc_party_sweep");

    // Party-count sweep: threshold fixed at 3, n grows.
    let threshold = 3u32;
    for party_count in [3usize, 7, 9] {
        group.bench_with_input(
            BenchmarkId::new("cmp20", format!("t={threshold}_n={party_count}")),
            &(threshold, party_count),
            |b, &(t, n)| {
                b.iter(|| {
                    let kg = confium_tc_cmp20::inprocess::keygen(t, n).unwrap();
                    confium_tc_cmp20::inprocess::sign(&kg.shares[..t as usize], t, b"bench")
                        .unwrap()
                });
            },
        );
    }

    group.finish();
}

fn bench_frost_p256(c: &mut Criterion) {
    let mut group = c.benchmark_group("frost_p256");

    group.bench_function("generate_keypair", |b| {
        b.iter(confium_tc_frost_p256::generate_keypair);
    });

    group.bench_function("split_5_of_3", |b| {
        let kp = confium_tc_frost_p256::generate_keypair();
        b.iter(|| confium_tc_frost_p256::shamir::split_secret(&kp.secret_scalar, 3, 5));
    });

    group.bench_function("recover_3_of_5", |b| {
        let kp = confium_tc_frost_p256::generate_keypair();
        let shares = confium_tc_frost_p256::shamir::split_secret(&kp.secret_scalar, 3, 5);
        let refs: Vec<_> = shares.iter().take(3).collect();
        b.iter(|| confium_tc_frost_p256::shamir::recover_secret(&refs).unwrap());
    });

    group.bench_function("sign_message", |b| {
        let kp = confium_tc_frost_p256::generate_keypair();
        b.iter(|| confium_tc_frost_p256::sign_message(&kp, b"bench").unwrap());
    });

    group.finish();
}

fn bench_p256_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256_verify");

    group.bench_function("verify_signature", |b| {
        let kp = confium_tc_frost_p256::generate_keypair();
        let signed = confium_tc_frost_p256::sign_message(&kp, b"bench").unwrap();
        let sig = Signature::from_der(&signed.der_bytes).unwrap();
        let vk = VerifyingKey::from_affine(kp.public_key).unwrap();
        b.iter(|| vk.verify(b"bench", &sig).unwrap());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_dkg_and_sign_threshold_sweep,
    bench_dkg_and_sign_party_sweep,
    bench_frost_p256,
    bench_p256_verify,
);
criterion_main!(benches);
