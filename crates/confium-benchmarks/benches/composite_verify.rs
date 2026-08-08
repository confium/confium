//! Composite signature verification benches.
//!
//! Measures:
//! - `CompositeSignature::verify` with one Ed25519 component
//! - `CompositeSignature::verify` with one ECDSA-P256 component
//! - `CompositeSignature::verify` with a hybrid Ed25519+ECDSA-P256 envelope

use confium_composite::{
    ComponentSignature, CompositeSignature, ECDSA_P256, ED25519, build_ed25519_component,
    build_p256_component, ed25519_verifier, p256_verifier,
};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand_core::OsRng;

fn make_ed25519_component(message: &[u8]) -> ComponentSignature {
    let signing = SigningKey::generate(&mut OsRng);
    build_ed25519_component(&signing, message).expect("ed25519 build")
}

fn make_p256_component(message: &[u8]) -> ComponentSignature {
    let signing = P256SigningKey::random(&mut OsRng);
    build_p256_component(&signing, message).expect("p256 build")
}

fn bench_composite_verify(c: &mut Criterion) {
    let message = b"benchmark-message-confium-composite-verify";

    let mut group = c.benchmark_group("composite_verify");
    group.throughput(Throughput::Elements(1));

    let ed = make_ed25519_component(message);
    let p256 = make_p256_component(message);

    let ed_only = CompositeSignature::new(vec![ed.clone()]);
    let p256_only = CompositeSignature::new(vec![p256.clone()]);
    let hybrid = CompositeSignature::new(vec![ed, p256]);

    group.bench_function(BenchmarkId::new("ed25519", "1_component"), |b| {
        b.iter(|| {
            black_box(&ed_only)
                .verify(black_box(message), |alg, pk, m, sig| {
                    ed25519_verifier(alg, pk, m, sig)
                })
                .unwrap();
        })
    });

    group.bench_function(BenchmarkId::new("ecdsa_p256", "1_component"), |b| {
        b.iter(|| {
            black_box(&p256_only)
                .verify(black_box(message), |alg, pk, m, sig| {
                    p256_verifier(alg, pk, m, sig)
                })
                .unwrap();
        })
    });

    group.bench_function(BenchmarkId::new("hybrid", "2_components"), |b| {
        b.iter(|| {
            black_box(&hybrid)
                .verify(black_box(message), |alg, pk, m, sig| match alg {
                    ED25519 => ed25519_verifier(alg, pk, m, sig),
                    ECDSA_P256 => p256_verifier(alg, pk, m, sig),
                    _ => unreachable!(),
                })
                .unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_composite_verify);
criterion_main!(benches);
