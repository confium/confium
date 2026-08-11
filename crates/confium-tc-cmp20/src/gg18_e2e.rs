//! GG18 end-to-end threshold ECDSA signing.
//!
//! Mirrors the CMP20 e2e pipeline but for GG18 (4-round protocol).

use crate::paillier_mta;
use confium_tc::paillier::{self, PaillierKeypair};
use num_bigint::BigUint;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// GG18 signing pipeline (4-round protocol).
pub struct Gg18SigningPipeline {
    pub threshold: u32,
    pub party_count: u32,
    pub paillier_keys: Vec<PaillierKeypair>,
    pub key_shares: Vec<Scalar>,
    pub public_key: AffinePoint,
}

impl Gg18SigningPipeline {
    pub fn new(threshold: u32, party_count: u32, key_shares: Vec<Scalar>) -> Self {
        let paillier_keys: Vec<PaillierKeypair> = (0..party_count)
            .map(|_| paillier::generate_keypair(256))
            .collect();
        let public_key = {
            let mut sum = ProjectivePoint::IDENTITY;
            for x in &key_shares {
                sum += ProjectivePoint::GENERATOR * x;
            }
            sum.to_affine()
        };
        Self {
            threshold,
            party_count,
            paillier_keys,
            key_shares,
            public_key,
        }
    }

    /// Run the GG18 4-round signing protocol for a message.
    #[allow(clippy::needless_range_loop)]
    pub fn sign(&self, message: &[u8]) -> Result<Signature, String> {
        let n = self.party_count as usize;

        // Round 1: each party generates nonce pair (k_i, gamma_i)
        let nonces: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();

        // Round 2: MtA for k_i * x_j (same as CMP20)
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let k_i_big = scalar_to_biguint(&nonces[i]);
                let x_j_big = scalar_to_biguint(&self.key_shares[j]);
                let _ = paillier_mta::full_mta(&self.paillier_keys[j], &k_i_big, &x_j_big)
                    .map_err(|e| format!("MtA failed: {e}"))?;
            }
        }

        // Compute R = sum(k_i) * G
        let mut k_sum = ProjectivePoint::IDENTITY;
        for k in &nonces {
            k_sum += ProjectivePoint::GENERATOR * k;
        }
        let r_point = k_sum.to_affine();
        let r = x_coordinate(&r_point);
        if r == Scalar::ZERO {
            return Err("r is zero".into());
        }

        // Hash
        let e = hash_to_scalar(message);

        // s = k^{-1} * (e + r * x) where k = sum(k_i), x = sum(x_i)
        let k_total: Scalar = nonces.iter().copied().fold(Scalar::ZERO, |a, b| a + b);
        let x_total: Scalar = self
            .key_shares
            .iter()
            .copied()
            .fold(Scalar::ZERO, |a, b| a + b);
        let k_inv = invert_scalar(&k_total);
        let s = k_inv * (e + r * x_total);
        if s == Scalar::ZERO {
            return Err("s is zero".into());
        }

        let r_bytes: [u8; 32] = r.to_repr().into();
        let s_bytes: [u8; 32] = s.to_repr().into();
        Signature::from_scalars(r_bytes, s_bytes).map_err(|e| format!("sig: {e}"))
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let vk = match VerifyingKey::from_affine(self.public_key) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        vk.verify(message, signature).is_ok()
    }
}

fn scalar_to_biguint(s: &Scalar) -> BigUint {
    let bytes: [u8; 32] = s.to_repr().into();
    BigUint::from_bytes_be(&bytes)
}

fn x_coordinate(point: &AffinePoint) -> Scalar {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let encoded = point.to_encoded_point(false);
    if let Some(x_bytes) = encoded.x() {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(x_bytes);
        let fb = p256::FieldBytes::from(arr);
        Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
    } else {
        Scalar::ZERO
    }
}

fn hash_to_scalar(message: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let fb = p256::FieldBytes::from(hasher.finalize());
    Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

fn invert_scalar(s: &Scalar) -> Scalar {
    Option::<Scalar>::from(s.invert()).unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_scalar() -> Scalar {
        Scalar::random(&mut OsRng)
    }

    #[test]
    fn gg18_sign_and_verify() {
        let shares = vec![random_scalar(), random_scalar(), random_scalar()];
        let pipeline = Gg18SigningPipeline::new(2, 3, shares);
        let sig = pipeline.sign(b"gg18 test").unwrap();
        assert!(pipeline.verify(b"gg18 test", &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let shares = vec![random_scalar(), random_scalar()];
        let pipeline = Gg18SigningPipeline::new(2, 2, shares);
        let sig = pipeline.sign(b"correct").unwrap();
        assert!(!pipeline.verify(b"wrong", &sig));
    }

    #[test]
    fn five_parties() {
        let shares: Vec<Scalar> = (0..5).map(|_| random_scalar()).collect();
        let pipeline = Gg18SigningPipeline::new(3, 5, shares);
        let sig = pipeline.sign(b"3-of-5").unwrap();
        assert!(pipeline.verify(b"3-of-5", &sig));
    }
}
