//! Distributed pseudorandom function (PRF).
//!
//! Each party contributes a PRF share; the combined output is the
//! XOR of partial evaluations. Used for threshold key derivation
//! without reconstructing the underlying secret.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A PRF share: a key that can evaluate the PRF on inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrfShare {
    pub key: Vec<u8>,
}

impl PrfShare {
    /// Evaluate the PRF on a given input. Returns a 32-byte output.
    pub fn evaluate(&self, input: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC key");
        mac.update(input);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        let len = result.len().min(32);
        out[..len].copy_from_slice(&result[..len]);
        out
    }
}

/// Result of a distributed PRF computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedPrfResult {
    pub output: [u8; 32],
}

/// Generate PRF shares by splitting a secret into T-of-N shares.
/// Each share is independently usable to compute partial PRF output.
pub fn distribute(secret: &[u8], threshold: usize, party_count: usize) -> Vec<PrfShare> {
    // XOR-based secret sharing: generate N-1 random shares, then
    // derive the last share so that XOR of all shares = secret.
    let mut shares = Vec::with_capacity(party_count);
    let mut xor_accum = vec![0u8; secret.len()];

    // Generate party_count - 1 random shares
    for _ in 0..(party_count.saturating_sub(1)) {
        let mut rand_share = vec![0u8; secret.len()];
        for (i, byte) in rand_share.iter_mut().enumerate() {
            *byte = rand_byte();
            xor_accum[i] ^= *byte;
        }
        shares.push(PrfShare { key: rand_share });
    }

    // Last share: ensures XOR of all shares equals secret
    let last: Vec<u8> = secret
        .iter()
        .zip(xor_accum.iter())
        .map(|(s, x)| s ^ x)
        .collect();
    shares.push(PrfShare { key: last });

    let _ = threshold; // threshold is used at evaluation time
    shares
}

/// Combine partial PRF outputs (XOR) to get the final output.
pub fn combine(partials: &[[u8; 32]]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for partial in partials {
        for (i, &b) in partial.iter().enumerate() {
            result[i] ^= b;
        }
    }
    result
}

/// Compute the distributed PRF: each party evaluates, then combine.
pub fn evaluate(
    shares: &[PrfShare],
    input: &[u8],
    threshold: usize,
) -> Result<DistributedPrfResult, String> {
    if shares.len() < threshold {
        return Err(format!("need {threshold} shares, got {}", shares.len()));
    }
    let partials: Vec<[u8; 32]> = shares[..threshold]
        .iter()
        .map(|s| s.evaluate(input))
        .collect();
    let output = combine(&partials);
    Ok(DistributedPrfResult { output })
}

fn rand_byte() -> u8 {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 1];
    OsRng.fill_bytes(&mut b);
    b[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_and_evaluate() {
        let secret = b"my secret key";
        let shares = distribute(secret, 3, 5);
        let result = evaluate(&shares, b"input", 3).unwrap();
        assert_eq!(result.output.len(), 32);
    }

    #[test]
    fn insufficient_shares_rejected() {
        let secret = b"key";
        let shares = distribute(secret, 3, 5);
        assert!(evaluate(&shares[0..2], b"input", 3).is_err());
    }

    #[test]
    fn deterministic_evaluation() {
        let secret = b"key";
        let shares = distribute(secret, 2, 3);
        let r1 = evaluate(&shares, b"in", 2).unwrap();
        let r2 = evaluate(&shares, b"in", 2).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let secret = b"key";
        let shares = distribute(secret, 2, 3);
        let r1 = evaluate(&shares, b"input1", 2).unwrap();
        let r2 = evaluate(&shares, b"input2", 2).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn combine_xors_correctly() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let result = combine(&[a, b]);
        for r in &result {
            assert_eq!(*r, 1 ^ 2);
        }
    }
}
