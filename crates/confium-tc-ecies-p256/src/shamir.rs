//! Real Shamir secret sharing over the P-256 scalar field.

use p256::elliptic_curve::rand_core;
use p256::elliptic_curve::subtle::CtOption;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{FieldBytes, Scalar};
use std::ops::{Add, Mul, Sub};

/// A Shamir share: (x, y).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Party index (1-based).
    pub x: u32,
    /// Share value.
    pub y: Scalar,
}

/// Split `secret` into `n` shares with threshold `t`.
pub fn split_secret(secret: &Scalar, t: u32, n: u32) -> Vec<Share> {
    assert!(t >= 1);
    assert!(n >= t);

    let mut coeffs: Vec<Scalar> = Vec::with_capacity(t as usize);
    coeffs.push(*secret);
    for _ in 1..t {
        coeffs.push(random_scalar());
    }

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

/// Recover the secret via Lagrange interpolation at x=0.
pub fn recover_secret(shares: &[&Share]) -> Result<Scalar, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::InsufficientShares { have: 0, need: 1 });
    }
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if !seen.insert(s.x) {
            return Err(ShamirError::DuplicateX(s.x));
        }
    }
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
            numerator = numerator.mul(&Scalar::ZERO.sub(&x_j));
            denominator = denominator.mul(&x_i.sub(&x_j));
        }
        let denom_inv = invert(&denominator);
        let lagrange = numerator.mul(&denom_inv);
        let term = s_i.y.mul(&lagrange);
        sum = sum.add(&term);
    }
    Ok(sum)
}

fn random_scalar() -> Scalar {
    Scalar::random(&mut rand_core::UnwrapErr(getrandom::SysRng))
}

fn evaluate_polynomial(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        result = result.mul(x);
        result = result.add(c);
    }
    result
}

fn u32_to_scalar(v: u32) -> Scalar {
    let mut arr = [0u8; 32];
    arr[28..32].copy_from_slice(&v.to_be_bytes());
    let fb = FieldBytes::from(arr);
    let ct: CtOption<Scalar> = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

fn invert(s: &Scalar) -> Scalar {
    let ct: CtOption<Scalar> = s.invert();
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

/// Shamir errors.
#[derive(Debug, thiserror::Error)]
pub enum ShamirError {
    /// Fewer than T shares provided.
    #[error("insufficient shares: have {have}, need {need}")]
    InsufficientShares {
        /// Count received.
        have: usize,
        /// Threshold.
        need: u32,
    },
    /// Duplicate x-coordinates.
    #[error("duplicate x: {0}")]
    DuplicateX(u32),
}
