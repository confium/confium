//! Multiplicative-to-Additive (MtA) sub-round.
//!
//! CMP20 signing needs to convert, for every pair `(i, j)`, the product
//! `k_i * x_j` into additive shares `alpha_{ij}` (held by `i`) and
//! `beta_{ji}` (held by `j`) such that `alpha_{ij} + beta_{ji} = k_i x_j`.
//!
//! The cryptographic way is Paillier homomorphic encryption (CMP20's
//! "key generation" already produces a Paillier keypair per party).
//! This crate does not depend on a Paillier backend, so the MtA is
//! computed **in the clear** inside the trusted test harness:
//! `alpha_{ij} = 0` and `beta_{ji} = k_i x_j`. The arithmetic outcome
//! is identical to a real MtA; only the cryptographic hiding is lost.
//! See the crate-level docs for what a production replacement requires.
//!
//! CMP20 folds the MtA products into the nonce-reveal round (round 2),
//! collapsing what would be two separate GG18 sub-rounds into one.

use p256::Scalar;

/// Collected per-party inputs for one signing session's MtA products.
#[derive(Clone, Debug)]
pub struct MtaInputs {
    pub ks: Vec<Scalar>,
    pub xs: Vec<Scalar>,
    pub indices: Vec<u64>,
}

impl MtaInputs {
    /// Compute additive MtA products for every ordered pair `(i, j)`.
    ///
    /// Simplified path: `alphas[i][j] = 0`, `betas[j][i] = k_i * x_j`.
    pub fn products(&self) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>) {
        let n = self.ks.len();
        let alphas = vec![vec![Scalar::ZERO; n]; n];
        let mut betas = vec![vec![Scalar::ZERO; n]; n];
        // Indexed matrix access (betas[j][i]) is clearer here than
        // an iterator rewrite; suppress the needless_range_loop hint.
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            #[allow(clippy::needless_range_loop)]
            for j in 0..n {
                if i == j {
                    continue;
                }
                betas[j][i] = self.ks[i] * self.xs[j];
            }
        }
        (alphas, betas)
    }
}

/// Party `i`'s total MtA adjustment:
/// `delta_i = k_i x_i + sum_{j != i} (alphas[j][i] + betas[i][j])`.
pub fn party_mta_sum(
    i: usize,
    ks: &[Scalar],
    xs: &[Scalar],
    alphas: &[Vec<Scalar>],
    betas: &[Vec<Scalar>],
) -> Scalar {
    let n = ks.len();
    let mut acc = ks[i] * xs[i];
    for j in 0..n {
        if j == i {
            continue;
        }
        acc += alphas[j][i];
        acc += betas[i][j];
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mta_products_sum_to_ki_xj() {
        let ks = vec![Scalar::from(2u64), Scalar::from(3u64), Scalar::from(5u64)];
        let xs = vec![Scalar::from(7u64), Scalar::from(11u64), Scalar::from(13u64)];
        let inputs = MtaInputs {
            ks: ks.clone(),
            xs: xs.clone(),
            indices: vec![1, 2, 3],
        };
        let (alphas, betas) = inputs.products();
        for i in 0..3 {
            for j in 0..3 {
                if i == j {
                    continue;
                }
                let sum = alphas[i][j] + betas[j][i];
                assert_eq!(sum, ks[i] * xs[j], "pair ({}, {})", i, j);
            }
        }
    }

    #[test]
    fn party_mta_sum_matches_xi_sum_kj() {
        let ks = vec![Scalar::from(2u64), Scalar::from(3u64), Scalar::from(5u64)];
        let xs = vec![Scalar::from(7u64), Scalar::from(11u64), Scalar::from(13u64)];
        let inputs = MtaInputs {
            ks: ks.clone(),
            xs: xs.clone(),
            indices: vec![1, 2, 3],
        };
        let (alphas, betas) = inputs.products();
        let k_sum: Scalar = ks.iter().copied().fold(Scalar::ZERO, |a, b| a + b);
        for i in 0..3 {
            let got = party_mta_sum(i, &ks, &xs, &alphas, &betas);
            assert_eq!(got, xs[i] * k_sum, "party {}", i);
        }
    }
}
