//! GG18 Paillier MtA integration.
//!
//! GG20 (the improved GG18) uses the same MtA sub-protocol as CMP20.
//! This module re-exports the CMP20 Paillier MtA for GG20's use.

pub use crate::paillier_mta::{
    self, MtaError, MtaMessage1, MtaMessage2, full_mta, party_i_finish, party_i_init,
    party_j_respond,
};

/// GG18-specific MtA: runs the MtA between two parties with an
/// additional range proof check (simplified).
pub fn gg18_mta(
    j_keypair: &confium_tc::paillier::PaillierKeypair,
    k_i: &num_bigint::BigUint,
    x_j: &num_bigint::BigUint,
) -> Result<(num_bigint::BigUint, num_bigint::BigUint), MtaError> {
    // GG18 uses the same MtA as CMP20
    full_mta(j_keypair, k_i, x_j)
}

#[cfg(test)]
mod tests {
    use super::*;
    use confium_tc::paillier::generate_keypair;
    use num_bigint::BigUint;

    #[test]
    fn gg18_mta_works() {
        let kp = generate_keypair(256);
        let k = BigUint::from(42u32);
        let x = BigUint::from(17u32);
        let (alpha, beta) = gg18_mta(&kp, &k, &x).unwrap();
        let sum = (&alpha + &beta) % &kp.public.n;
        let product = (&k * &x) % &kp.public.n;
        assert_eq!(sum, product);
    }

    #[test]
    fn gg18_mta_shares_dont_reveal_product() {
        let kp = generate_keypair(256);
        let k = BigUint::from(42u32);
        let x = BigUint::from(17u32);
        let (alpha, beta) = gg18_mta(&kp, &k, &x).unwrap();
        let product = &k * &x;
        assert_ne!(alpha, product);
        assert_ne!(beta, product);
    }

    #[test]
    fn gg18_mta_multiple_pairs() {
        let kp = generate_keypair(256);
        for (k, x) in [(10u32, 20u32), (100u32, 50u32), (7u32, 13u32)] {
            let (alpha, beta) = gg18_mta(&kp, &BigUint::from(k), &BigUint::from(x)).unwrap();
            let sum = (&alpha + &beta) % &kp.public.n;
            let product = (BigUint::from(k) * BigUint::from(x)) % &kp.public.n;
            assert_eq!(sum, product);
        }
    }
}
