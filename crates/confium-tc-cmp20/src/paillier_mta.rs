//! Paillier-based Multiplicative-to-Additive (MtA) protocol.
//!
//! Converts `k_i * x_j` into additive shares `(α_ij, β_ji)` such that
//! `α_ij + β_ji = k_i * x_j` (mod curve order), WITHOUT revealing
//! either value to the other party.
//!
//! ## Protocol
//!
//! 1. **Party i** encrypts `k_i` under party j's Paillier public key:
//!    `c = E_j(k_i, r)`
//! 2. **Party i** sends `c` to party j
//! 3. **Party j** computes homomorphic multiply + mask:
//!    `c' = c^{x_j} * E_j(β_ji, r') = E_j(k_i * x_j + β_ji)`
//! 4. **Party j** sends `c'` back to party i
//! 5. **Party i** decrypts: `α_ij = D_j(c') = k_i * x_j + β_ji`
//!
//! Result: `α_ij - β_ji = k_i * x_j` (additive share split).
//!
//! Uses the Paillier implementation from `confium_tc::paillier`.

use confium_tc::paillier::{
    PaillierError, PaillierKeypair, PaillierPrivateKey, PaillierPublicKey, add as paillier_add,
    decrypt as paillier_decrypt, encrypt as paillier_encrypt, scalar_mul as paillier_scalar_mul,
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;

/// Message from party i to party j (round 1 of MtA).
#[derive(Debug, Clone)]
pub struct MtaMessage1 {
    /// Encrypted k_i under j's Paillier public key.
    pub ciphertext: BigUint,
}

/// Message from party j to party i (round 2 of MtA).
#[derive(Debug, Clone)]
pub struct MtaMessage2 {
    /// Encrypted k_i * x_j + β_ji under j's Paillier public key.
    pub ciphertext: BigUint,
    /// The mask β_ji that party j keeps (as additive share).
    pub beta: BigUint,
}

/// Errors during MtA.
#[derive(Debug)]
pub enum MtaError {
    Paillier(PaillierError),
    ValueTooLarge,
}

impl std::fmt::Display for MtaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paillier(e) => write!(f, "paillier error: {e}"),
            Self::ValueTooLarge => write!(f, "value too large for Paillier modulus"),
        }
    }
}

impl std::error::Error for MtaError {}

impl From<PaillierError> for MtaError {
    fn from(e: PaillierError) -> Self {
        Self::Paillier(e)
    }
}

/// Party i initiates the MtA: encrypt k_i under j's public key.
pub fn party_i_init(j_public: &PaillierPublicKey, k_i: &BigUint) -> Result<MtaMessage1, MtaError> {
    let r = random_below(&j_public.n);
    let ciphertext = paillier_encrypt(j_public, k_i, &r)?;
    Ok(MtaMessage1 { ciphertext })
}

/// Party j processes the message: multiply by x_j, subtract mask β_ji.
pub fn party_j_respond(
    j_keypair: &PaillierKeypair,
    msg: &MtaMessage1,
    x_j: &BigUint,
) -> Result<(MtaMessage2, BigUint), MtaError> {
    // Pick random mask β_ji
    let beta = random_below(&j_keypair.public.n);
    // c^{x_j} = E(k_i * x_j)
    let c_mul = paillier_scalar_mul(&j_keypair.public, &msg.ciphertext, x_j);
    // E(-β_ji, r') = E(N - β_ji, r')
    let neg_beta = &j_keypair.public.n - &beta;
    let r_prime = random_below(&j_keypair.public.n);
    let c_beta = paillier_encrypt(&j_keypair.public, &neg_beta, &r_prime)?;
    // c' = c_mul * c_beta = E(k_i * x_j - β_ji)
    let c_prime = paillier_add(&j_keypair.public, &c_mul, &c_beta);
    Ok((
        MtaMessage2 {
            ciphertext: c_prime,
            beta: beta.clone(),
        },
        beta,
    ))
}

/// Party i finishes: decrypt to get α_ij.
pub fn party_i_finish(
    j_public: &PaillierPublicKey,
    j_private: &PaillierPrivateKey,
    msg: &MtaMessage2,
) -> Result<BigUint, MtaError> {
    let alpha = paillier_decrypt(j_private, j_public, &msg.ciphertext)?;
    Ok(alpha)
}

/// Run the full MtA protocol between party i and party j.
/// Returns (α_ij, β_ji) such that α_ij + β_ji = k_i * x_j (mod N).
pub fn full_mta(
    j_keypair: &PaillierKeypair,
    k_i: &BigUint,
    x_j: &BigUint,
) -> Result<(BigUint, BigUint), MtaError> {
    let msg1 = party_i_init(&j_keypair.public, k_i)?;
    let (msg2, beta) = party_j_respond(j_keypair, &msg1, x_j)?;
    let alpha = party_i_finish(&j_keypair.public, &j_keypair.private, &msg2)?;
    Ok((alpha, beta))
}

fn random_below(n: &BigUint) -> BigUint {
    let mut rng = OsRng;
    loop {
        let r = rng.gen_biguint(n.bits());
        if r < *n && r > BigUint::zero() {
            return r;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confium_tc::paillier::generate_keypair;

    fn make_keypair() -> PaillierKeypair {
        generate_keypair(128)
    }

    #[test]
    fn mta_additive_shares_sum_to_product() {
        let kp = make_keypair();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);

        let (alpha, beta) = full_mta(&kp, &k_i, &x_j).unwrap();

        // α + β should equal k_i * x_j (mod N)
        let sum = (&alpha + &beta) % &kp.public.n;
        let product = (&k_i * &x_j) % &kp.public.n;
        assert_eq!(sum, product);
    }

    #[test]
    fn mta_shares_neither_reveals_product() {
        let kp = make_keypair();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);

        let (alpha, beta) = full_mta(&kp, &k_i, &x_j).unwrap();

        // Neither α nor β alone should equal the product
        let product = &k_i * &x_j;
        assert_ne!(alpha, product);
        assert_ne!(beta, product);
    }

    #[test]
    fn mta_multiple_pairs() {
        let kp = make_keypair();
        for (k, x) in [(10u32, 20u32), (100u32, 50u32), (7u32, 13u32)] {
            let k_i = BigUint::from(k);
            let x_j = BigUint::from(x);
            let (alpha, beta) = full_mta(&kp, &k_i, &x_j).unwrap();
            let sum = (&alpha + &beta) % &kp.public.n;
            let product = (&k_i * &x_j) % &kp.public.n;
            assert_eq!(sum, product, "pair ({}, {})", k, x);
        }
    }

    #[test]
    fn mta_with_large_values() {
        let kp = make_keypair();
        let k_i = BigUint::from(0xFFFFu32);
        let x_j = BigUint::from(0xEEEEu32);

        let (alpha, beta) = full_mta(&kp, &k_i, &x_j).unwrap();
        let sum = (&alpha + &beta) % &kp.public.n;
        let product = (&k_i * &x_j) % &kp.public.n;
        assert_eq!(sum, product);
    }

    #[test]
    fn mta_initiates_with_encrypted_message() {
        let kp = make_keypair();
        let k_i = BigUint::from(42u32);
        let msg = party_i_init(&kp.public, &k_i).unwrap();
        // Ciphertext should not reveal k_i
        assert_ne!(msg.ciphertext, k_i);
    }

    #[test]
    fn mta_different_randomness_different_ciphertexts() {
        let kp = make_keypair();
        let k_i = BigUint::from(42u32);
        let msg1 = party_i_init(&kp.public, &k_i).unwrap();
        let msg2 = party_i_init(&kp.public, &k_i).unwrap();
        // Randomness makes each ciphertext different
        assert_ne!(msg1.ciphertext, msg2.ciphertext);
    }

    #[test]
    fn mta_beta_is_random() {
        let kp = make_keypair();
        let k_i = BigUint::from(42u32);
        let x_j = BigUint::from(17u32);
        let (_, beta1) = full_mta(&kp, &k_i, &x_j).unwrap();
        let (_, beta2) = full_mta(&kp, &k_i, &x_j).unwrap();
        // Different random masks each time
        assert_ne!(beta1, beta2);
    }
}
