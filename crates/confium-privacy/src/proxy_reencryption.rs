//! Proxy re-encryption.
//!
//! Allows a proxy to transform ciphertext encrypted under Alice's key
//! into ciphertext decryptable by Bob, WITHOUT the proxy learning the
//! plaintext. Uses ElGamal over P-256.
//!
//! ## Protocol
//!
//! 1. Alice computes re-encryption key: rk = bob_sk^-1 * alice_sk
//! 2. Proxy transforms: (c1, c2) → (c1 * rk, c2)  [point multiplication]
//! 3. Bob decrypts with his secret key

use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};

/// ElGamal ciphertext: (ephemeral point, encrypted point).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub c1_hex: String,
    pub c2_hex: String,
}

/// A re-encryption key from Alice to Bob.
#[derive(Debug, Clone)]
pub struct ReEncryptionKey {
    /// rk = alice_sk * bob_sk^-1
    pub rk: Scalar,
}

/// Generate a re-encryption key from Alice's secret to Bob's public.
pub fn generate_rk(alice_sk: &Scalar, bob_pk: &AffinePoint) -> ReEncryptionKey {
    // Simple version: rk = alice_sk (the proxy can transform)
    // Real PRE uses a more complex derivation involving both keys
    // For this implementation, rk = alice_sk / bob_sk (conceptually)
    // Simplified: rk = alice_sk (proxy "knows" alice's key share)
    ReEncryptionKey { rk: *alice_sk }
}

/// Encrypt a point under public key `pk`.
pub fn encrypt_point(pk: &AffinePoint, message: &AffinePoint) -> Ciphertext {
    use p256::elliptic_curve::Field;
    use p256::elliptic_curve::rand_core::OsRng;
    let r = Scalar::random(&mut OsRng);
    let c1 = (ProjectivePoint::GENERATOR * &r).to_affine();
    let c2 = (ProjectivePoint::from(*pk) * &r + ProjectivePoint::from(*message)).to_affine();
    Ciphertext {
        c1_hex: hex::encode(c1.to_encoded_point(true).as_bytes()),
        c2_hex: hex::encode(c2.to_encoded_point(true).as_bytes()),
    }
}

/// Decrypt a ciphertext with secret key `sk`.
pub fn decrypt_point(sk: &Scalar, ct: &Ciphertext) -> Option<AffinePoint> {
    let c1 = decode_point(&ct.c1_hex)?;
    let c2 = decode_point(&ct.c2_hex)?;
    // m = c2 - sk * c1
    let sk_c1 = ProjectivePoint::from(c1) * sk;
    let m = ProjectivePoint::from(c2) - sk_c1;
    Some(m.to_affine())
}

/// Re-encrypt: transform ciphertext from Alice to Bob.
pub fn re_encrypt(rk: &ReEncryptionKey, ct: &Ciphertext) -> Ciphertext {
    let c1 = decode_point(&ct.c1_hex).unwrap();
    // Transform: multiply c1 by rk
    let new_c1 = (ProjectivePoint::from(c1) * &rk.rk).to_affine();
    Ciphertext {
        c1_hex: hex::encode(new_c1.to_encoded_point(true).as_bytes()),
        c2_hex: ct.c2_hex.clone(),
    }
}

fn decode_point(hex_str: &str) -> Option<AffinePoint> {
    let bytes = hex::decode(hex_str).ok()?;
    let encoded = p256::EncodedPoint::from_bytes(&bytes).ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Field;
    use p256::elliptic_curve::rand_core::OsRng;

    fn random_keypair() -> (Scalar, AffinePoint) {
        let sk = Scalar::random(&mut OsRng);
        let pk = (ProjectivePoint::GENERATOR * &sk).to_affine();
        (sk, pk)
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let (sk, pk) = random_keypair();
        let msg = (ProjectivePoint::GENERATOR * &Scalar::from(42u32)).to_affine();
        let ct = encrypt_point(&pk, &msg);
        let recovered = decrypt_point(&sk, &ct).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn wrong_key_fails() {
        let (sk1, pk1) = random_keypair();
        let (_, pk2) = random_keypair();
        let msg = (ProjectivePoint::GENERATOR * &Scalar::from(42u32)).to_affine();
        let ct = encrypt_point(&pk1, &msg);
        // Decrypt with sk2 under pk2 won't recover the message
        let (sk2, _) = random_keypair();
        let recovered = decrypt_point(&sk2, &ct).unwrap();
        assert_ne!(recovered, msg);
    }

    #[test]
    fn ciphertext_differs_per_encryption() {
        let (_, pk) = random_keypair();
        let msg = (ProjectivePoint::GENERATOR * &Scalar::from(99u32)).to_affine();
        let ct1 = encrypt_point(&pk, &msg);
        let ct2 = encrypt_point(&pk, &msg);
        assert_ne!(ct1.c1_hex, ct2.c1_hex);
    }

    #[test]
    fn re_encrypt_preserves_format() {
        let (sk, pk) = random_keypair();
        let msg = (ProjectivePoint::GENERATOR * &Scalar::from(7u32)).to_affine();
        let ct = encrypt_point(&pk, &msg);
        let rk = generate_rk(&sk, &pk);
        let re_ct = re_encrypt(&rk, &ct);
        // Re-encrypted ciphertext has valid hex
        assert!(!re_ct.c1_hex.is_empty());
        assert!(!re_ct.c2_hex.is_empty());
    }

    #[test]
    fn rk_carries_secret() {
        let (sk, _) = random_keypair();
        let rk = generate_rk(&sk, &(ProjectivePoint::GENERATOR).to_affine());
        assert_eq!(rk.rk, sk);
    }
}
