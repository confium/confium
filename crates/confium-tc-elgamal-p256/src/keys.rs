//! Keypair generation for threshold ElGamal-P256.

use p256::elliptic_curve::rand_core;
use p256::elliptic_curve::rand_core::RngCore;
use p256::elliptic_curve::subtle::CtOption;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

/// A P-256 keypair.
#[derive(Debug, Clone)]
pub struct Keypair {
    /// Secret scalar.
    pub secret_scalar: Scalar,
    /// Public key (affine point).
    pub public_key: AffinePoint,
}

/// Generate a fresh random keypair.
pub fn generate_keypair() -> Keypair {
    let secret = loop {
        let mut buf = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut buf);
        if let Some(s) = CtOption::into(Scalar::from_repr(FieldBytes::from(buf))) {
            if s != Scalar::ZERO {
                break s;
            }
        }
    };
    let public = public_key_for(&secret);
    Keypair {
        secret_scalar: secret,
        public_key: public,
    }
}

/// Compute the public key for a given secret scalar.
pub fn public_key_for(secret: &Scalar) -> AffinePoint {
    let g = ProjectivePoint::GENERATOR;
    (g * secret).to_affine()
}
