//! Criterion benchmark: simulate an N-party threshold signing session.
//!
//! Measures wall time and message bytes for one full protocol run. The
//! benchmark registers a deterministic mock scheme that performs a
//! fixed number of rounds (broadcast each round, complete on the last)
//! so the comparison across candidate schemes is apples-to-apples —
//! the transport, routing, and harness overhead are what vary, not the
//! crypto math.
//!
//! Real candidate schemes register themselves via the same
//! `inventory::submit!` mechanism; swapping the mock for a real plugin
//! is a one-line change in the scheme registration below.

use std::time::Duration;

use confium_tc::Message;
use confium_tc::SessionParams;
use confium_tc::registry::{RegisteredScheme, RoundResult, SessionImpl, TcScheme, TcSchemeKind};
use confium_test_harness::{TestVector, VectorRunner};
use criterion::Criterion;

criterion::criterion_group! {
    name = sim;
    config = Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(3));
    targets = bench_sim_session, bench_routing_only
}
criterion::criterion_main!(sim);

/// A mock scheme that runs exactly `ROUNDS` rounds, broadcasting a
/// fixed-size payload each round. Reproducible, no real crypto — keeps
/// the benchmark focused on harness + transport overhead.
struct BenchScheme;

const ROUNDS: u8 = 3;
const PAYLOAD_BYTES: usize = 256;

impl TcScheme for BenchScheme {
    fn name(&self) -> &'static str {
        "bench-mock"
    }
    fn kind(&self) -> TcSchemeKind {
        TcSchemeKind::Signature
    }
    fn create_session(&self, _params: &SessionParams) -> confium_tc::Result<Box<dyn SessionImpl>> {
        Ok(Box::new(BenchSession {
            round: 0,
            our_id: "bench-party".to_string(),
        }))
    }
}

struct BenchSession {
    round: u8,
    our_id: String,
}

impl SessionImpl for BenchSession {
    fn round(&mut self, _incoming: &[Message]) -> confium_tc::Result<RoundResult> {
        self.round += 1;
        if self.round >= ROUNDS {
            return Ok(RoundResult::done());
        }
        let payload = vec![0u8; PAYLOAD_BYTES];
        let msg = Message::broadcast(&self.our_id, self.round, payload);
        Ok(RoundResult::new(vec![msg], false))
    }
    fn result(&self) -> confium_tc::Result<Vec<u8>> {
        Ok(vec![0u8; 64])
    }
    fn destroy(&mut self) {}
}

inventory::submit! {
    RegisteredScheme { scheme: &BenchScheme as &dyn TcScheme }
}

fn bench_sim_session(c: &mut Criterion) {
    let mut group = c.benchmark_group("sim_session");
    for parties in [3, 5, 10, 25] {
        let threshold = (parties / 2).max(1);
        group.bench_function(format!("parties={parties}"), |b| {
            b.iter(|| {
                let vector = TestVector {
                    scheme: confium_test_harness::vector::SchemeSpec {
                        name: "bench-mock".into(),
                        version: "bench".into(),
                    },
                    test: confium_test_harness::vector::TestVectorTest {
                        parties,
                        threshold,
                        message: "bench".into(),
                        seed: "0x1".into(),
                        expected_signature_hex: String::new(),
                    },
                    peer_behavior: Vec::new(),
                    conformance_level: Default::default(),
                    reference: None,
                    expected_round_count: None,
                    share_material: None,
                };
                VectorRunner::run(&vector).expect("bench run must succeed")
            });
        });
    }
    group.finish();
}

/// Isolate the Byzantine routing + transport overhead from the session
/// machinery: drive the routing layer alone with a fixed message batch.
fn bench_routing_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("routing_only");
    for parties in [5, 25, 100] {
        group.bench_function(format!("parties={parties}"), |b| {
            let msgs: Vec<Message> = (0..parties)
                .map(|i| Message::broadcast(format!("p{i}"), 1, vec![0u8; PAYLOAD_BYTES]))
                .collect();
            b.iter(|| {
                // Fresh transport per iteration: the replay buffer
                // accumulates state, so we rebuild to keep each sample
                // measuring one route() call, not history growth.
                let mut tport = confium_test_harness::ByzantineTransport::new();
                tport.route(&msgs)
            });
        });
    }
    group.finish();
}
