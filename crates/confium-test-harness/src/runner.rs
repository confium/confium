//! Vector runner: execute one [`TestVector`] against a registered TC
//! scheme and produce a [`TestResult`].
//!
//! The runner stands up one [`confium_tc::Session`] per party, drives
//! every session forward one round at a time, routes all outgoing
//! messages through a [`crate::ByzantineTransport`] (so configured
//! behaviors take effect), and feeds the surviving messages back as
//! the next round's incoming set. When every session reports
//! `complete`, it reads the result and compares it against the
//! vector's expected bytes.
//!
//! The runner is the integration point between the deterministic
//! environment, the Byzantine wrapper, and the link-time scheme
//! registry. NIST evaluators point it at a vector file plus a
//! `confium install`-ed scheme name; everything else is automatic.
//!
//! Schemes under test are resolved via the link-time
//! [`confium_tc::registry`] — the same mechanism real plugins use.
//! Tests that want to drive a mock scheme register it via
//! `inventory::submit!` (see the tests at the bottom of this file).

use std::time::Instant;

use confium_tc::Message;
use confium_tc::Party;
use confium_tc::PartyList;
use confium_tc::Session;
use confium_tc::SessionParams;

use crate::ByzantineTransport;
use crate::DeterministicEnv;
use crate::Result;
use crate::TestResult;
use crate::TestVector;
use crate::error::SessionDidNotCompleteSnafu;

/// Maximum rounds before the runner gives up. Generous — real
/// threshold schemes are 3–7 rounds; this is a safety valve against a
/// buggy scheme that never completes.
const MAX_ROUNDS: u8 = 64;

/// Drives a vector through a registered TC scheme.
pub struct VectorRunner;

impl VectorRunner {
    /// Execute `vector` against the scheme resolved from
    /// `vector.scheme.name` via the link-time registry.
    ///
    /// All parties run in-process in the calling thread, round by
    /// round. The deterministic env is seeded from the vector; the
    /// Byzantine transport applies the vector's per-party behaviors.
    pub fn run(vector: &TestVector) -> Result<TestResult> {
        let started = Instant::now();

        // The env exists for side effects (clock, memory) that schemes
        // under test consult. Seeded from the vector so transcripts are
        // reproducible.
        let _env = DeterministicEnv::from_seed(vector.seed_u64()?);
        let mut tport = ByzantineTransport::from_specs(vector.behavior_specs());

        let parties = build_party_list(vector);
        let message_bytes = vector.test.message_bytes();

        // One session per party. Session::create resolves the scheme
        // from the link-time registry, same path real plugins take.
        let mut sessions: Vec<Session> = Vec::with_capacity(parties.len());
        for idx in 0..parties.len() {
            let params = SessionParams {
                scheme: vector.scheme.name.clone(),
                parties: parties.clone(),
                threshold: vector.test.threshold,
                this_party_idx: idx,
                local_share: None,
                message: Some(message_bytes.clone()),
            };
            let session = Session::create(&params)?;
            sessions.push(session);
        }

        let mut total_messages: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut round: u8 = 0;
        let last_output;

        // Pending incoming messages per party index, populated by the
        // previous round's routing.
        let mut incoming: Vec<Vec<Message>> = vec![Vec::new(); sessions.len()];

        loop {
            round = round
                .checked_add(1)
                .ok_or_else(|| SessionDidNotCompleteSnafu { rounds: round }.build())?;
            if round > MAX_ROUNDS {
                return Err(SessionDidNotCompleteSnafu { rounds: round }.build());
            }

            // Step every non-complete session.
            let mut outgoing_all: Vec<Message> = Vec::new();
            let mut all_complete = true;
            for (idx, session) in sessions.iter_mut().enumerate() {
                if session.is_complete() {
                    continue;
                }
                let my_id = parties.get(idx)?.id.clone();
                let incoming_for_me = incoming[idx]
                    .iter()
                    .filter(|m| m.is_for(&my_id) && m.from_party_id != my_id)
                    .cloned()
                    .collect::<Vec<_>>();
                let rr = session.round_step(&incoming_for_me)?;
                for msg in &rr.outgoing {
                    total_messages += 1;
                    total_bytes += msg.payload.len() as u64;
                }
                outgoing_all.extend(rr.outgoing);
                if !session.is_complete() {
                    all_complete = false;
                }
            }

            // Route the round's outgoing through the Byzantine wrapper.
            let delivered = tport.route(&outgoing_all);

            // Partition delivered messages into next round's incoming
            // buckets per recipient party.
            for bucket in incoming.iter_mut() {
                bucket.clear();
            }
            for msg in delivered {
                let recipients: Vec<usize> = match &msg.to_party_id {
                    None => (0..parties.len()).collect(),
                    Some(to) => parties
                        .parties()
                        .iter()
                        .position(|p| &p.id == to)
                        .into_iter()
                        .collect(),
                };
                for ridx in recipients {
                    if let Some(bucket) = incoming.get_mut(ridx) {
                        bucket.push(msg.clone());
                    }
                }
            }

            if all_complete {
                // Read the result from the first session; threshold
                // schemes produce identical output on every party.
                last_output = sessions
                    .first()
                    .map(|s| s.result().unwrap_or_default())
                    .unwrap_or_default();
                break;
            }
        }

        let elapsed = started.elapsed();
        Ok(TestResult::from_run(
            vector,
            last_output,
            total_messages,
            total_bytes,
            round,
            elapsed,
        ))
    }

    /// Convenience: parse a vector from a path and run it.
    pub fn run_path(path: &std::path::Path) -> Result<TestResult> {
        let vector = TestVector::from_path(path)?;
        Self::run(&vector)
    }
}

/// Build the [`PartyList`] for a vector. If the vector declares
/// `[[peer_behavior]]` entries for all parties, use those ids in
/// order; otherwise synthesize `p0..pN-1` and prepend any declared ids.
fn build_party_list(vector: &TestVector) -> PartyList {
    let n = vector.test.parties as usize;
    if vector.peer_behavior.len() == n {
        let parties = vector
            .peer_behavior
            .iter()
            .map(|e| Party::inproc(e.party_id.clone()))
            .collect();
        PartyList::from_parties(parties)
    } else if !vector.peer_behavior.is_empty() {
        // Partial: use declared ids first, then synthesize the rest.
        let mut parties: Vec<Party> = vector
            .peer_behavior
            .iter()
            .map(|e| Party::inproc(e.party_id.clone()))
            .collect();
        for i in vector.peer_behavior.len()..n {
            parties.push(Party::inproc(format!("p{i}")));
        }
        PartyList::from_parties(parties)
    } else {
        let parties = (0..n).map(|i| Party::inproc(format!("p{i}"))).collect();
        PartyList::from_parties(parties)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::SchemeSpec;
    use crate::vector::TestVectorTest;
    use confium_tc::Message;
    use confium_tc::error;
    use confium_tc::registry::{RoundResult, SessionImpl, TcScheme, TcSchemeKind};

    /// A no-op mock scheme that "completes" on round 1, echoing the
    /// input message as the output. Registered at link time via
    /// `inventory::submit!` so the runner can resolve it the same way
    /// it resolves real plugins.
    struct RunnerMockScheme;

    impl TcScheme for RunnerMockScheme {
        fn name(&self) -> &'static str {
            "runner-mock"
        }
        fn kind(&self) -> TcSchemeKind {
            TcSchemeKind::Signature
        }
        fn create_session(
            &self,
            params: &SessionParams,
        ) -> confium_tc::Result<Box<dyn SessionImpl>> {
            Ok(Box::new(RunnerMockSession {
                msg: params.message.clone().unwrap_or_default(),
                done: false,
            }))
        }
    }

    struct RunnerMockSession {
        msg: Vec<u8>,
        done: bool,
    }

    impl SessionImpl for RunnerMockSession {
        fn round(&mut self, _incoming: &[Message]) -> confium_tc::Result<RoundResult> {
            self.done = true;
            Ok(RoundResult::done())
        }
        fn result(&self) -> confium_tc::Result<Vec<u8>> {
            if !self.done {
                return Err(error::SessionNotCompleteSnafu {}.build());
            }
            Ok(self.msg.clone())
        }
        fn destroy(&mut self) {
            self.msg.fill(0);
        }
    }

    inventory::submit! {
        confium_tc::registry::RegisteredScheme {
            scheme: &RunnerMockScheme as &dyn TcScheme
        }
    }

    fn sample_vector(expected: Option<&str>) -> TestVector {
        TestVector {
            scheme: SchemeSpec {
                name: "runner-mock".into(),
                version: "test".into(),
            },
            test: TestVectorTest {
                parties: 3,
                threshold: 2,
                message: "hello".into(),
                seed: "0x42".into(),
                expected_signature_hex: expected.unwrap_or("").to_string(),
            },
            peer_behavior: vec![],
        }
    }

    fn hex_str(bytes: &[u8]) -> String {
        let mut s = String::from("0x");
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn runner_completes_mock_scheme_and_passes() {
        let expected = hex_str(b"hello");
        let vector = sample_vector(Some(&expected));
        let result = VectorRunner::run(&vector).expect("run succeeds");
        assert_eq!(result.outcome, crate::Outcome::Pass);
        assert_eq!(result.output, b"hello");
        assert_eq!(result.rounds, 1);
    }

    #[test]
    fn runner_passes_without_expected_bytes() {
        let vector = sample_vector(None);
        let result = VectorRunner::run(&vector).unwrap();
        assert_eq!(result.outcome, crate::Outcome::Pass);
    }

    #[test]
    fn runner_records_zero_messages_for_noop_scheme() {
        let vector = sample_vector(None);
        let result = VectorRunner::run(&vector).unwrap();
        assert_eq!(result.messages_exchanged, 0);
        assert_eq!(result.bytes_exchanged, 0);
    }

    #[test]
    fn runner_fails_when_output_mismatches_expected() {
        let vector = sample_vector(Some("0xdeadbeef"));
        let result = VectorRunner::run(&vector).unwrap();
        assert_eq!(result.outcome, crate::Outcome::Fail);
    }
}
