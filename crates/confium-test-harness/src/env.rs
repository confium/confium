//! Deterministic environment for reproducible NIST evaluation runs.
//!
//! A [`DeterministicEnv`] bundles the four knobs a vector needs to be
//! replayable bit-for-bit across machines and runs:
//!
//! - a seeded [`DeterministicRng`] (a Splittable-style PRNG built on
//!   `rand_chacha`'s design without pulling in `rand` — we seed a simple
//!   ChaCha8-like counter stream here, but the concrete implementation is
//!   a 128-bit splitmix64 that is fully self-contained)
//! - a [`DeterministicClock`] that advances only when the harness tells
//!   it to (no wall-clock dependence, no flaky timeouts)
//! - a [`MemoryCounter`] that tallies bytes the harness attributes to a
//!   party so the bench can report peak allocation per scheme
//!
//! The harness never reads the OS clock or `getrandom` directly — every
//! source of nondeterminism is funneled through this module so the same
//! vector + seed yields the same transcript every time.

use std::cell::Cell;
use std::sync::Mutex;

/// Self-contained deterministic PRNG.
///
/// A 64-bit splitmix64 generator seeded from the vector's `seed` field.
/// Same seed, same call sequence, same bytes — no platform entropy. The
/// stream is reproducible across machines, which is the whole point for
/// NIST vectors.
///
/// Not cryptographically secure — this exists to make protocol
/// transcripts reproducible, not to be the production RNG. Schemes under
/// test plug this in via their nonce/ephemeral-value hooks.
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Seed a fresh generator. A zero seed is allowed and produces a
    /// well-defined stream (the first output is non-zero because
    /// splitmix64 mixes the state before returning).
    pub fn from_seed(seed: u64) -> Self {
        DeterministicRng { state: seed }
    }

    /// Next raw 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        // splitmix64 — identical to the algorithm in the reference
        // test-vector literature, so cross-language reimplementations
        // can match byte-for-byte.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Fill `out` with deterministic bytes derived from the stream.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= out.len() {
            let w = self.next_u64().to_le_bytes();
            out[i..i + 8].copy_from_slice(&w);
            i += 8;
        }
        if i < out.len() {
            let w = self.next_u64().to_le_bytes();
            let remaining = out.len() - i;
            out[i..].copy_from_slice(&w[..remaining]);
        }
    }
}

/// Stepping clock that ignores wall time.
///
/// The harness calls [`DeterministicClock::advance`] between rounds;
/// `now` returns the accumulated nanoseconds. Timeouts in protocol
/// plugins should consult this (via the env handle) rather than
/// `SystemTime`, so a slow CI box doesn't trip a timeout the vector
/// never intended to fire.
#[derive(Debug, Default)]
pub struct DeterministicClock {
    nanos: Cell<u128>,
}

impl DeterministicClock {
    pub fn new() -> Self {
        DeterministicClock {
            nanos: Cell::new(0),
        }
    }

    /// Current simulated time in nanoseconds since env start.
    pub fn now_nanos(&self) -> u128 {
        self.nanos.get()
    }

    /// Advance the clock by `nanos`. Monotonic; never goes backwards.
    pub fn advance(&self, nanos: u64) {
        self.nanos
            .set(self.nanos.get().saturating_add(nanos as u128));
    }
}

/// Per-party allocation tally.
///
/// The harness calls [`MemoryCounter::track`] when a plugin reports it
/// has allocated on behalf of a party; the counter keeps a running peak.
/// This is cooperative accounting — the framework can't intercept every
/// `malloc` — but it gives the bench a consistent, comparable number
/// across schemes that all play by the same rule.
#[derive(Debug, Default)]
pub struct MemoryCounter {
    inner: Mutex<MemoryState>,
}

#[derive(Debug, Default, Clone, Copy)]
struct MemoryState {
    current: u64,
    peak: u64,
}

impl MemoryCounter {
    pub fn new() -> Self {
        MemoryCounter::default()
    }

    /// Account `bytes` of live allocation. Updates the peak if the new
    /// current exceeds it.
    pub fn track(&self, bytes: u64) {
        let mut state = self.inner.lock().expect("memory counter poisoned");
        state.current = state.current.saturating_add(bytes);
        if state.current > state.peak {
            state.peak = state.current;
        }
    }

    /// Release previously tracked bytes. Never underflows past zero.
    pub fn release(&self, bytes: u64) {
        let mut state = self.inner.lock().expect("memory counter poisoned");
        state.current = state.current.saturating_sub(bytes);
    }

    /// Highest live-allocation watermark seen since construction.
    pub fn peak_bytes(&self) -> u64 {
        self.inner.lock().expect("memory counter poisoned").peak
    }

    /// Currently live tracked bytes.
    pub fn current_bytes(&self) -> u64 {
        self.inner.lock().expect("memory counter poisoned").current
    }
}

/// The four-knob deterministic bundle handed to a vector run.
///
/// Construct with [`DeterministicEnv::from_seed`]; pass clones into each
/// party. The RNG is the only piece that must not be shared between
/// parties — give each party its own fork via [`DeterministicEnv::fork`]
/// so their streams diverge deterministically by party index.
#[derive(Debug)]
pub struct DeterministicEnv {
    seed: u64,
    clock: DeterministicClock,
    memory: MemoryCounter,
}

impl DeterministicEnv {
    /// Build an env rooted at `seed`. All forked RNGs derive from this.
    pub fn from_seed(seed: u64) -> Self {
        DeterministicEnv {
            seed,
            clock: DeterministicClock::new(),
            memory: MemoryCounter::new(),
        }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// A fresh RNG for party `idx`. Mixing the party index into the seed
    /// means two parties never share a stream but the assignment is
    /// still deterministic for a given (env seed, roster).
    pub fn rng_for(&self, party_idx: usize) -> DeterministicRng {
        let mixed = self
            .seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(party_idx as u64);
        DeterministicRng::from_seed(mixed)
    }

    /// Fork this env for a child party: shares the clock and memory
    /// counter (those are session-wide) but yields a party-specific RNG.
    pub fn fork(&self, party_idx: usize) -> ForkedEnv<'_> {
        ForkedEnv {
            rng: self.rng_for(party_idx),
            clock: &self.clock,
            memory: &self.memory,
        }
    }

    pub fn clock(&self) -> &DeterministicClock {
        &self.clock
    }

    pub fn memory(&self) -> &MemoryCounter {
        &self.memory
    }
}

/// Per-party view of a [`DeterministicEnv`]: its own RNG, borrowed clock
/// and memory counter shared with siblings.
#[derive(Debug, Clone)]
pub struct ForkedEnv<'a> {
    pub rng: DeterministicRng,
    pub clock: &'a DeterministicClock,
    pub memory: &'a MemoryCounter,
}

impl<'a> ForkedEnv<'a> {
    /// Borrow the per-party RNG mutably for nonce / ephemeral generation.
    pub fn rng_mut(&mut self) -> &mut DeterministicRng {
        &mut self.rng
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_rng_is_reproducible() {
        let mut a = DeterministicRng::from_seed(0xDEAD_BEEF_CAFE_BABE);
        let mut b = DeterministicRng::from_seed(0xDEAD_BEEF_CAFE_BABE);
        for _ in 0..32 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = DeterministicRng::from_seed(1);
        let mut b = DeterministicRng::from_seed(2);
        // Overwhelmingly likely to differ at least once in 16 draws.
        let differs = (0..16).any(|_| a.next_u64() != b.next_u64());
        assert!(differs, "two different seeds produced identical streams");
    }

    #[test]
    fn zero_seed_still_produces_output() {
        let mut rng = DeterministicRng::from_seed(0);
        // splitmix64 mixes before returning, so zero seed is not a fixed
        // point.
        let first = rng.next_u64();
        let second = rng.next_u64();
        assert_ne!(first, second);
    }

    #[test]
    fn fill_is_byte_reproducible() {
        let mut a = [0u8; 17];
        let mut b = [0u8; 17];
        DeterministicRng::from_seed(42).fill(&mut a);
        DeterministicRng::from_seed(42).fill(&mut b);
        assert_eq!(a, b);
        assert!(a.iter().any(|&x| x != 0));
    }

    #[test]
    fn clock_starts_at_zero_and_advances() {
        let clock = DeterministicClock::new();
        assert_eq!(clock.now_nanos(), 0);
        clock.advance(1_000_000_000);
        assert_eq!(clock.now_nanos(), 1_000_000_000);
        clock.advance(500_000_000);
        assert_eq!(clock.now_nanos(), 1_500_000_000);
    }

    #[test]
    fn clock_does_not_overflow() {
        let clock = DeterministicClock::new();
        clock.advance(u64::MAX);
        clock.advance(u64::MAX);
        assert!(clock.now_nanos() > u64::MAX as u128);
    }

    #[test]
    fn memory_counter_tracks_peak() {
        let mem = MemoryCounter::new();
        mem.track(100);
        mem.track(200);
        assert_eq!(mem.current_bytes(), 300);
        assert_eq!(mem.peak_bytes(), 300);
        mem.release(150);
        assert_eq!(mem.current_bytes(), 150);
        assert_eq!(mem.peak_bytes(), 300, "peak is sticky");
        mem.track(400);
        assert_eq!(mem.peak_bytes(), 550);
    }

    #[test]
    fn memory_counter_release_underflows_to_zero() {
        let mem = MemoryCounter::new();
        mem.release(1_000_000);
        assert_eq!(mem.current_bytes(), 0);
        assert_eq!(mem.peak_bytes(), 0);
    }

    #[test]
    fn env_forks_diverge_by_party_index() {
        let env = DeterministicEnv::from_seed(99);
        let mut fork_a = env.fork(0);
        let mut fork_b = env.fork(1);
        let x = fork_a.rng_mut().next_u64();
        let y = fork_b.rng_mut().next_u64();
        assert_ne!(
            x, y,
            "two parties must not share an RNG stream in the same session"
        );
    }

    #[test]
    fn env_fork_shares_clock_and_memory() {
        let env = DeterministicEnv::from_seed(7);
        let fork_a = env.fork(0);
        let fork_b = env.fork(1);
        fork_a.memory.track(128);
        assert_eq!(fork_b.memory.peak_bytes(), 128);
        fork_a.clock.advance(5);
        assert_eq!(fork_b.clock.now_nanos(), 5);
    }
}
