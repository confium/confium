//! Keypair generation for threshold P-256.

use crate::scalar;
use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    AffinePoint, ProjectivePoint, Scalar,
};

/// A P-256 keypair.
#[derive(Debug, Clone)]
pub struct Keypair {
    /// Secret scalar.
    pub secret_scalar: Scalar,
    /// Public key (affine point).
    pub public_key: AffinePoint,
}

impl Keypair {
    /// Convert to `p256::ecdsa::SigningKey`.
    pub fn to_signing_key(&self) -> SigningKey {
        let bytes = scalar::scalar_to_bytes(&self.secret_scalar);
        SigningKey::from_bytes((&bytes).into()).expect("scalar is in valid range")
    }

    /// Convert to `p256::ecdsa::VerifyingKey`.
    pub fn to_verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_affine(self.public_key).expect("public key is valid")
    }
}

/// Generate a fresh random keypair.
pub fn generate_keypair() -> Keypair {
    let secret = loop {
        let s = scalar::random_scalar();
        if s != Scalar::ZERO {
            break s;
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
    let p = g * secret;
    p.to_affine()
}

/// SEC1-encoded public key bytes (uncompressed, 65 bytes).
pub fn public_key_sec1(affine: &AffinePoint) -> Vec<u8> {
    affine.to_encoded_point(false).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation_is_unique() {
        let k1 = generate_keypair();
        let k2 = generate_keypair();
        assert_ne!(k1.secret_scalar, k2.secret_scalar);
        assert_ne!(k1.public_key, k2.public_key);
    }

    #[test]
    fn secret_to_public_is_deterministic() {
        let k = generate_keypair();
        let pk_again = public_key_for(&k.secret_scalar);
        assert_eq!(pk_again, k.public_key);
    }

    #[test]
    fn public_key_sec1_is_65_bytes_uncompressed() {
        let k = generate_keypair();
        let bytes = public_key_sec1(&k.public_key);
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
    }
}
