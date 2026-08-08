//! P-256 scalar field helpers.
//!
//! Wraps `p256::Scalar` operations needed for Shamir secret sharing
//! and Lagrange interpolation.

use p256::elliptic_curve::subtle::CtOption;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{FieldBytes, Scalar};
use std::ops::Mul;

/// Convert raw big-endian bytes (32 bytes) into a `Scalar`.
/// Returns None if bytes are not 32 long or if the value is out of range.
pub fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let fb = FieldBytes::from(arr);
    let ct: CtOption<Scalar> = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct)
}

/// Convert a `Scalar` to 32 big-endian bytes.
pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    let fb: FieldBytes = s.to_bytes();
    fb.into()
}

/// Add two scalars.
pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    a.add(b)
}

/// Multiply two scalars.
pub fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    a.mul(b)
}

/// Subtract one scalar from another.
pub fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    a.sub(b)
}

/// Modular inverse of a scalar (1/a mod n). Returns ZERO if `a` is zero.
pub fn scalar_invert(a: &Scalar) -> Scalar {
    let ct: CtOption<Scalar> = a.invert();
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

/// Generate a random scalar.
pub fn random_scalar() -> Scalar {
    Scalar::random(rand_core::OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_round_trip() {
        let s = random_scalar();
        let bytes = scalar_to_bytes(&s);
        let recovered = scalar_from_bytes(&bytes).unwrap();
        assert_eq!(s, recovered);
    }

    #[test]
    fn scalar_add_inverse_of_sub() {
        let a = random_scalar();
        let b = random_scalar();
        let sum = scalar_add(&a, &b);
        let back = scalar_sub(&sum, &b);
        assert_eq!(back, a);
    }

    #[test]
    fn scalar_invert_mul_is_identity() {
        let a = random_scalar();
        if a == Scalar::ZERO {
            return;
        }
        let inv = scalar_invert(&a);
        let product = scalar_mul(&a, &inv);
        assert_eq!(product, Scalar::ONE);
    }

    #[test]
    fn rejects_wrong_length_bytes() {
        assert!(scalar_from_bytes(&[0u8; 16]).is_none());
    }
}
