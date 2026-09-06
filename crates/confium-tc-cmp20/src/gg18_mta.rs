//! GG18 Paillier MtA integration.
//!
//! GG20 (the improved GG18) uses the same MtA sub-protocol as CMP20.
//! This module re-exports the CMP20 Paillier MtA for GG20's use.

// `full_mta` re-exported for source compatibility with the
// deprecated signature.
#[allow(deprecated)]
pub use crate::paillier_mta::{
    self, MtaError, MtaMessage1, MtaMessage2, full_mta, full_mta_proved, party_i_finish,
    party_i_init, party_j_respond,
};

/// GG18-specific MtA: identical sub-protocol to CMP20 (both per
/// Gennaro-Goldfeder), now with the Appendix A proofs on every
/// ciphertext.
#[allow(clippy::too_many_arguments)]
pub fn gg18_mta(
    j_keypair: &confium_tc::paillier::PaillierKeypair,
    ck_i: &crate::mta_proofs::CommitmentKey,
    ck_j: &crate::mta_proofs::CommitmentKey,
    q: &num_bigint::BigUint,
    k_i: &num_bigint::BigUint,
    x_j: &num_bigint::BigUint,
) -> Result<(num_bigint::BigUint, num_bigint::BigUint), MtaError> {
    full_mta_proved(j_keypair, ck_i, ck_j, q, k_i, x_j)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mta_proofs::p256_order;
    use confium_tc::paillier::generate_keypair;
    use num_bigint::BigUint;
    use std::sync::OnceLock;

    fn fixtures() -> &'static (
        confium_tc::paillier::PaillierKeypair,
        crate::mta_proofs::CommitmentKey,
        crate::mta_proofs::CommitmentKey,
        BigUint,
    ) {
        static FIX: OnceLock<(
            confium_tc::paillier::PaillierKeypair,
            crate::mta_proofs::CommitmentKey,
            crate::mta_proofs::CommitmentKey,
            BigUint,
        )> = OnceLock::new();
        FIX.get_or_init(|| {
            // 642-bit primes: honest proofs need N > q⁵ + q².
            (
                generate_keypair(642),
                crate::mta_proofs::generate_commitment_key(64),
                crate::mta_proofs::generate_commitment_key(64),
                p256_order(),
            )
        })
    }

    #[test]
    fn gg18_mta_works() {
        let (kp, ck_i, ck_j, q) = fixtures();
        let k = BigUint::from(42u32);
        let x = BigUint::from(17u32);
        let (alpha, beta) = gg18_mta(kp, ck_i, ck_j, q, &k, &x).unwrap();
        assert_eq!((&alpha - &beta) % q, (&k * &x) % q);
    }

    #[test]
    fn gg18_mta_shares_dont_reveal_product() {
        let (kp, ck_i, ck_j, q) = fixtures();
        let k = BigUint::from(42u32);
        let x = BigUint::from(17u32);
        let (alpha, beta) = gg18_mta(kp, ck_i, ck_j, q, &k, &x).unwrap();
        let product = &k * &x;
        assert_ne!(alpha, product);
        assert_ne!(beta, product);
    }

    #[test]
    fn gg18_mta_multiple_pairs() {
        let (kp, ck_i, ck_j, q) = fixtures();
        for (k, x) in [(10u32, 20u32), (100u32, 50u32), (7u32, 13u32)] {
            let (alpha, beta) =
                gg18_mta(kp, ck_i, ck_j, q, &BigUint::from(k), &BigUint::from(x)).unwrap();
            assert_eq!(
                (&alpha - &beta) % q,
                (BigUint::from(k) * BigUint::from(x)) % q
            );
        }
    }
}
