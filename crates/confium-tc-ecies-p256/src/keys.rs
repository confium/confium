//! Keypair generation for threshold ECIES-P256.

use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::rand_core;
use p256::elliptic_curve::rand_core::Rng;
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
        rand_core::UnwrapErr(getrandom::SysRng).fill_bytes(&mut buf);
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(buf))) {
            if s != Scalar::ZERO {
                break s;
            }
        }
    };
    let public = (ProjectivePoint::GENERATOR * secret).to_affine();
    Keypair {
        secret_scalar: secret,
        public_key: public,
    }
}
