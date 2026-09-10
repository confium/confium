//! Verifiable Delay Function (VDF).
//!
//! A Wesolowski-style VDF: forces sequential computation (repeated
//! squaring) and produces a proof that the delay was executed.
//!
//! ## Protocol
//!
//! 1. Setup: pick RSA modulus N = p * q
//! 2. Eval: y = x^(2^T) mod N (requires T sequential squarings)
//! 3. Proof: π = x^⌊2^T / l⌋ mod N where l is the prime nearest
//!    above hash(y, x)
//! 4. Verify: with r = 2^T mod l, check y == π^l · x^r (mod N)
//!    (the Wesolowski relation — 2^T = l·q + r and y = (x^q)^l · x^r)

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

/// VDF public parameters.
#[derive(Debug, Clone)]
pub struct VdfParams {
    /// RSA modulus N.
    pub n: BigUint,
    /// Delay parameter T (number of squarings).
    pub t: u64,
}

/// VDF output with proof.
#[derive(Debug, Clone)]
pub struct VdfOutput {
    /// The result y = x^(2^T) mod N.
    pub y: BigUint,
    /// Wesolowski proof π.
    pub proof: BigUint,
}

/// Generate VDF parameters with a fresh RSA modulus.
pub fn setup(t: u64, prime_bits: u32) -> VdfParams {
    let p = generate_prime(prime_bits);
    let q = generate_prime(prime_bits);
    let n = &p * &q;
    VdfParams { n, t }
}

/// Evaluate the VDF: compute y = x^(2^T) mod N and proof.
/// This is the slow part — T sequential squarings.
pub fn eval(params: &VdfParams, x: &BigUint) -> VdfOutput {
    let mut y = x.clone();
    for _ in 0..params.t {
        y = (&y * &y) % &params.n;
    }

    // Generate prime l from hash(y, x)
    let l = hash_to_prime(&y, x);

    // Compute proof: π = x^(2^T // l) mod N
    let exponent = BigUint::one() << params.t;
    let quotient = &exponent / &l;
    let proof = x.modpow(&quotient, &params.n);

    VdfOutput { y, proof }
}

/// Verify a VDF output without recomputing the delay.
pub fn verify(params: &VdfParams, x: &BigUint, output: &VdfOutput) -> bool {
    let l = hash_to_prime(&output.y, x);

    // Wesolowski relation: write 2^T = l·q + r with q = ⌊2^T/l⌋ and
    // r = 2^T mod l. Then y = x^(2^T) = (x^q)^l · x^r = π^l · x^r.
    let two_t = BigUint::one() << params.t;
    let r = &two_t % &l;
    let pi_l = output.proof.modpow(&l, &params.n);
    let x_r = x.modpow(&r, &params.n);
    let rhs = (&pi_l * x_r) % &params.n;

    output.y == rhs
}

/// Derive the Wesolowski prime: hash to an odd candidate, then
/// search upward until Miller-Rabin accepts. l must be an actual
/// prime — a composite l admits multiple valid witnesses and breaks
/// the uniqueness argument the soundness proof relies on.
fn hash_to_prime(y: &BigUint, x: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"vdf-prime");
    hasher.update(y.to_bytes_be());
    hasher.update(x.to_bytes_be());
    let mut candidate = BigUint::from_bytes_be(&hasher.finalize()) | BigUint::one();
    if candidate < BigUint::from(3u32) {
        candidate = BigUint::from(3u32);
    }
    loop {
        if miller_rabin(&candidate, 20) {
            return candidate;
        }
        candidate += 2u32;
    }
}

fn generate_prime(bits: u32) -> BigUint {
    let mut rng = OsRng;
    loop {
        if bits < 2 {
            continue;
        }
        let top = BigUint::one() << (bits - 1);
        let candidate = rng.gen_biguint(bits as u64) | top | BigUint::one();
        if miller_rabin(&candidate, 20) {
            return candidate;
        }
    }
}

/// Miller-Rabin probable-prime test — the same algorithm and round
/// count as confium-tc's paillier keygen (kept local so the privacy
/// crate does not pull the whole TC stack for one function).
fn miller_rabin(n: &BigUint, rounds: u32) -> bool {
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    if n == &two || n == &three {
        return true;
    }
    if (n & &BigUint::one()) == BigUint::from(0u32) || n < &three {
        return false;
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;

    let mut d = n_minus_one.clone();
    let mut r: u32 = 0;
    loop {
        if (&d & &one) == BigUint::from(0u32) {
            d >>= 1;
            r += 1;
        } else {
            break;
        }
    }

    let mut rng = OsRng;
    'outer: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &n_minus_one);
        if a < two || a >= n_minus_one {
            continue;
        }
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = (&x * &x) % n;
            if x == n_minus_one {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_params(t: u64) -> VdfParams {
        setup(t, 128)
    }

    #[test]
    fn eval_produces_output() {
        let params = make_params(100);
        let x = BigUint::from(42u32);
        let output = eval(&params, &x);
        assert!(output.y > BigUint::from(0u32));
        assert!(output.proof > BigUint::from(0u32));
    }

    #[test]
    fn verify_accepts_correct_output() {
        let params = make_params(50);
        let x = BigUint::from(123u32);
        let output = eval(&params, &x);
        assert!(verify(&params, &x, &output));
    }

    #[test]
    fn verify_rejects_tampered_proof() {
        let params = make_params(50);
        let x = BigUint::from(123u32);
        let output = eval(&params, &x);
        let tampered = VdfOutput {
            y: output.y.clone(),
            proof: &output.proof + BigUint::one(),
        };
        assert!(!verify(&params, &x, &tampered));
    }

    #[test]
    fn verify_rejects_tampered_output() {
        let params = make_params(50);
        let x = BigUint::from(123u32);
        let output = eval(&params, &x);
        let tampered = VdfOutput {
            y: &output.y + BigUint::one(),
            proof: output.proof.clone(),
        };
        assert!(!verify(&params, &x, &tampered));
    }

    #[test]
    fn verify_rejects_wrong_input() {
        let params = make_params(50);
        let x = BigUint::from(123u32);
        let output = eval(&params, &x);
        // Valid proof, wrong claimed input.
        assert!(!verify(&params, &BigUint::from(124u32), &output));
    }

    #[test]
    fn eval_is_deterministic() {
        let params = make_params(100);
        let x = BigUint::from(999u32);
        let y1 = eval(&params, &x).y;
        let y2 = eval(&params, &x).y;
        assert_eq!(y1, y2);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let params = make_params(50);
        let y1 = eval(&params, &BigUint::from(1u32)).y;
        let y2 = eval(&params, &BigUint::from(2u32)).y;
        assert_ne!(y1, y2);
    }

    #[test]
    fn zero_delay_returns_input() {
        let params = make_params(0);
        let x = BigUint::from(42u32);
        let output = eval(&params, &x);
        assert_eq!(output.y, x % &params.n);
    }

    #[test]
    fn large_delay_completes() {
        let params = make_params(1000);
        let x = BigUint::from(7u32);
        let output = eval(&params, &x);
        assert!(output.y < params.n);
    }

    #[test]
    fn hash_to_prime_returns_an_actual_prime() {
        let y = BigUint::from(42u32);
        let x = BigUint::from(99u32);
        let l = hash_to_prime(&y, &x);
        assert!(l > BigUint::from(2u32));
        assert!((l.clone() & &BigUint::one()) == BigUint::one());
        assert!(miller_rabin(&l, 20));
    }

    #[test]
    fn hash_to_prime_is_deterministic() {
        let y = BigUint::from(42u32);
        let x = BigUint::from(99u32);
        let p1 = hash_to_prime(&y, &x);
        let p2 = hash_to_prime(&y, &x);
        assert_eq!(p1, p2);
    }
}
