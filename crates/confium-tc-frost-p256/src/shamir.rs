//! Real Shamir secret sharing over the P-256 scalar field.
//!
//! Splits a `Scalar` secret into N shares using a random polynomial
//! of degree T-1. Any T shares can reconstruct the secret via Lagrange
//! interpolation.

use crate::scalar;
use p256::elliptic_curve::PrimeField;
use p256::Scalar;

/// A Shamir share: (x, y) where x is the party index and y is a scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Party index (the x-coordinate). Typically 1-based per FROST convention.
    pub x: u32,
    /// The share value (the y-coordinate).
    pub y: Scalar,
}

/// Errors during Shamir operations.
#[derive(Debug, thiserror::Error)]
pub enum ShamirError {
    /// Fewer than T shares provided for recovery.
    #[error("insufficient shares: have {have}, need at least {need}")]
    InsufficientShares {
        /// Count received.
        have: usize,
        /// Threshold.
        need: u32,
    },
    /// Duplicate x-coordinates would cause divide-by-zero.
    #[error("duplicate x-coordinate: {0}")]
    DuplicateX(u32),
}

/// Split a `secret` into `n` shares with threshold `t`. Any `t` of the
/// `n` shares can reconstruct the secret.
///
/// Polynomial: f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
/// Share i: (i, f(i)) for i in 1..=n
pub fn split_secret(secret: &Scalar, t: u32, n: u32) -> Vec<Share> {
    assert!(t >= 1, "threshold must be at least 1");
    assert!(n >= t, "n must be >= t");

    // Generate random polynomial coefficients
    let mut coeffs: Vec<Scalar> = Vec::with_capacity(t as usize);
    coeffs.push(*secret);
    for _ in 1..t {
        coeffs.push(scalar::random_scalar());
    }

    // Evaluate polynomial at x = 1, 2, ..., n
    (1..=n)
        .map(|i| {
            let x = u32_to_scalar(i);
            Share {
                x: i,
                y: evaluate_polynomial(&coeffs, &x),
            }
        })
        .collect()
}

fn evaluate_polynomial(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    // Horner's method
    let mut result = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        result = scalar::scalar_mul(&result, x);
        result = scalar::scalar_add(&result, c);
    }
    result
}

fn u32_to_scalar(v: u32) -> Scalar {
    let mut arr = [0u8; 32];
    arr[28..32].copy_from_slice(&v.to_be_bytes());
    let fb = p256::FieldBytes::from(arr);
    let ct: p256::elliptic_curve::subtle::CtOption<Scalar> = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

/// Recover the secret (the polynomial evaluated at x=0) from at least
/// `t` shares via Lagrange interpolation.
pub fn recover_secret(shares: &[&Share]) -> Result<Scalar, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::InsufficientShares {
            have: 0,
            need: 1,
        });
    }

    // Check for duplicate x values
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if !seen.insert(s.x) {
            return Err(ShamirError::DuplicateX(s.x));
        }
    }

    // Lagrange interpolation at x=0:
    // f(0) = sum_i y_i * prod_{j != i} (0 - x_j) / (x_i - x_j)
    let mut sum = Scalar::ZERO;
    for s_i in shares {
        let x_i = u32_to_scalar(s_i.x);
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for s_j in shares {
            if s_j.x == s_i.x {
                continue;
            }
            let x_j = u32_to_scalar(s_j.x);
            // numerator *= (0 - x_j) = -x_j
            numerator = scalar::scalar_mul(&numerator, &scalar::scalar_sub(&Scalar::ZERO, &x_j));
            // denominator *= (x_i - x_j)
            denominator = scalar::scalar_mul(&denominator, &scalar::scalar_sub(&x_i, &x_j));
        }
        let denom_inv = scalar::scalar_invert(&denominator);
        let lagrange_coeff = scalar::scalar_mul(&numerator, &denom_inv);
        let term = scalar::scalar_mul(&s_i.y, &lagrange_coeff);
        sum = scalar::scalar_add(&sum, &term);
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_reconstruct_at_threshold() {
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, 3, 5);
        let subset: Vec<&Share> = shares.iter().take(3).collect();
        let recovered = recover_secret(&subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn different_threshold_subsets_same_secret() {
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, 3, 5);
        let subset_a: Vec<&Share> = vec![&shares[0], &shares[1], &shares[2]];
        let subset_b: Vec<&Share> = vec![&shares[2], &shares[3], &shares[4]];
        assert_eq!(recover_secret(&subset_a).unwrap(), secret);
        assert_eq!(recover_secret(&subset_b).unwrap(), secret);
    }

    #[test]
    fn duplicate_x_fails() {
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, 3, 5);
        let subset: Vec<&Share> = vec![&shares[0], &shares[0]];
        let result = recover_secret(&subset);
        assert!(matches!(result, Err(ShamirError::DuplicateX(_))));
    }

    #[test]
    fn empty_shares_fail() {
        let result = recover_secret(&[]);
        assert!(matches!(result, Err(ShamirError::InsufficientShares { .. })));
    }

    #[test]
    fn threshold_one() {
        let secret = scalar::random_scalar();
        let shares = split_secret(&secret, 1, 3);
        let subset: Vec<&Share> = vec![&shares[0]];
        let recovered = recover_secret(&subset).unwrap();
        assert_eq!(recovered, secret);
    }
}
