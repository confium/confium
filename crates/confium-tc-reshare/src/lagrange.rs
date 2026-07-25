//! Lagrange interpolation helpers for share re-sharing.
//!
//! Re-sharing works by computing Lagrange interpolation of existing
//! shares at new party indices. The result is a new share that is
//! consistent with the same aggregate secret.

use serde::{Deserialize, Serialize};

/// A field element for Lagrange interpolation. Stored as raw bytes;
/// the algorithm-specific crate (FROST, CMP20, etc.) interprets them
/// per the underlying curve/group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldElement(pub Vec<u8>);

impl FieldElement {
    /// Construct a new field element.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Compute the Lagrange coefficient λ_i(x) evaluated at point `x`,
/// given the set of x-coordinates `xs` and the index `i`.
///
/// For threshold schemes, this is typically computed modulo a prime
/// that depends on the curve/group. This crate provides the algorithmic
/// skeleton; concrete modprime arithmetic lives in the algorithm crates.
pub fn lagrange_basis_at(
    xs: &[u64],
    i: usize,
    x: u64,
    op_eval: &impl Fn(i128) -> i128,
    op_mul: &impl Fn(i128, i128) -> i128,
    op_div: &impl Fn(i128, i128) -> i128,
) -> i128 {
    let xi = xs[i] as i128;
    let mut result = 1i128;
    for (j, &xj) in xs.iter().enumerate() {
        if j == i {
            continue;
        }
        let xj_i128 = xj as i128;
        let x_i128 = x as i128;
        let numerator = op_eval(x_i128 - xj_i128);
        let denominator = op_eval(xi - xj_i128);
        result = op_mul(result, op_div(numerator, denominator));
    }
    result
}

/// Compute the new share for party at index `target_x` given existing
/// (x, y) pairs and arithmetic ops. This is the core of re-sharing.
pub fn interpolate_at(
    points: &[(u64, FieldElement)],
    target_x: u64,
    op_eval: &impl Fn(i128) -> i128,
    op_mul: &impl Fn(i128, i128) -> i128,
    op_add: &impl Fn(i128, i128) -> i128,
    op_div: &impl Fn(i128, i128) -> i128,
) -> FieldElement {
    let xs: Vec<u64> = points.iter().map(|(x, _)| *x).collect();
    let mut result = 0i128;
    for (i, (_, y)) in points.iter().enumerate() {
        let lambda = lagrange_basis_at(&xs, i, target_x, op_eval, op_mul, op_div);
        let y_val = i128::from_be_bytes(y.0[..16].try_into().unwrap_or([0u8; 16]));
        result = op_add(result, op_mul(lambda, y_val));
    }
    FieldElement::new(result.to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integer arithmetic helpers for testing.
    fn id(x: i128) -> i128 {
        x
    }
    fn mul(a: i128, b: i128) -> i128 {
        a * b
    }
    fn add(a: i128, b: i128) -> i128 {
        a + b
    }
    fn div(a: i128, b: i128) -> i128 {
        if b == 0 {
            panic!("division by zero");
        }
        a / b
    }

    #[test]
    fn lagrange_basis_two_points() {
        // Two points: (1, 5), (2, 7). Linear interpolation: y = 2x + 3
        // λ_0 at x=0 = (0-2)/(1-2) = 2
        let xs = vec![1, 2];
        let result = lagrange_basis_at(&xs, 0, 0, &id, &mul, &div);
        assert_eq!(result, 2);
    }

    #[test]
    fn interpolate_recovers_secret() {
        // y = 2x + 3, so secret at x=0 is 3
        // Points: (1, 5), (2, 7)
        // Encode as FieldElements with 16-byte big-endian.
        let points = vec![
            (1u64, FieldElement::new(5i128.to_be_bytes().to_vec())),
            (2u64, FieldElement::new(7i128.to_be_bytes().to_vec())),
        ];
        let result = interpolate_at(&points, 0, &id, &mul, &add, &div);
        let recovered = i128::from_be_bytes(result.0[..16].try_into().unwrap());
        assert_eq!(recovered, 3);
    }
}
