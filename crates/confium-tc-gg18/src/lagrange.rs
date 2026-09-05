//! Lagrange interpolation in the P-256 scalar field.
//!
//! Both DKG verification and signing combine `T` per-party values that
//! were generated as evaluations of a degree-`T-1` polynomial. The
//! combination is a Lagrange-basis-weighted sum evaluated at `x = 0`:
//!
//! `f(0) = \sum_i \lambda_i \cdot y_i`, where
//! `\lambda_i = \prod_{j \ne i} \frac{-x_j}{x_i - x_j}` and `x_k` is
//! party `k`'s 1-based roster index.

use p256::Scalar;

/// Compute the Lagrange basis coefficient `\lambda_i` for evaluating
/// the polynomial at `x = 0`, given the full set of participating
/// x-coords `xs` and the specific coordinate `xi`.
pub fn lagrange_basis_scalar(xi: Scalar, xs: &[Scalar]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &xj in xs {
        if xj == xi {
            continue;
        }
        num *= -xj;
        den *= xi - xj;
    }
    // Garbage-in-garbage-out on zero input; protocol callers pass
    // non-zero scalars (sweep ledger: SEC-audit-notes).
    let den_inv = den.invert().unwrap_or(Scalar::ZERO);
    num * den_inv
}

/// Apply Lagrange interpolation at `x = 0` to `(x_i, y_i)` pairs.
pub fn lagrange_weighted_sum(pairs: &[(Scalar, Scalar)]) -> Scalar {
    let xs: Vec<Scalar> = pairs.iter().map(|(x, _)| *x).collect();
    let mut acc = Scalar::ZERO;
    for (i, &(_, yi)) in pairs.iter().enumerate() {
        let lam = lagrange_basis_scalar(xs[i], &xs);
        acc += lam * yi;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(i: u32) -> Scalar {
        Scalar::from(i)
    }

    #[test]
    fn lagrange_recovers_secret_for_2_of_3() {
        let a0 = Scalar::from(42u64);
        let a1 = Scalar::from(7u64);
        let y1 = a0 + a1 * idx(1);
        let y2 = a0 + a1 * idx(2);
        let recovered = lagrange_weighted_sum(&[(idx(1), y1), (idx(2), y2)]);
        assert_eq!(recovered, a0);
    }

    #[test]
    fn lagrange_recovers_secret_for_3_of_3() {
        let a0 = Scalar::from(123u64);
        let a1 = Scalar::from(4u64);
        let a2 = Scalar::from(9u64);
        let eval = |x: Scalar| a0 + a1 * x + a2 * x * x;
        let recovered = lagrange_weighted_sum(&[
            (idx(1), eval(idx(1))),
            (idx(2), eval(idx(2))),
            (idx(3), eval(idx(3))),
        ]);
        assert_eq!(recovered, a0);
    }

    #[test]
    fn lagrange_any_t_subset_recovers_same_secret() {
        // Degree-1 polynomial (threshold T=2): any 2 of the 3
        // evaluations recover the secret.
        let a0 = Scalar::from(99u64);
        let a1 = Scalar::from(2u64);
        let eval = |x: Scalar| a0 + a1 * x;
        let all: [(Scalar, Scalar); 3] = [
            (idx(1), eval(idx(1))),
            (idx(2), eval(idx(2))),
            (idx(3), eval(idx(3))),
        ];
        for (i, j) in [(0usize, 1), (0, 2), (1, 2)] {
            let subset = [all[i], all[j]];
            let r = lagrange_weighted_sum(&subset);
            assert_eq!(r, a0, "2-of-3 subset must recover secret");
        }
        let r = lagrange_weighted_sum(&all);
        assert_eq!(r, a0);
    }

    #[test]
    fn lagrange_handles_degree_zero() {
        let a0 = Scalar::from(7u64);
        let r = lagrange_weighted_sum(&[(idx(1), a0)]);
        assert_eq!(r, a0);
    }
}
