//! Schnorr proof of knowledge — non-interactive ZK proof of discrete log.
//!
//! Proves knowledge of `x` such that `Y = g^x`, without revealing `x`.
//! Uses the Fiat-Shamir heuristic: the challenge is derived from a
//! hash of the protocol transcript, making the proof non-interactive.

use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A Schnorr proof: (R, z) serialized as hex strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrProof {
    /// Commitment point R = g^k (SEC1 compressed, hex).
    pub r_hex: String,
    /// Response scalar z = k + c*x (32 bytes, hex).
    pub z_hex: String,
}

/// Errors during proof operations.
#[derive(Debug, thiserror::Error)]
pub enum SchnorrError {
    /// Point decoding failed.
    #[error("point decoding failed")]
    InvalidPoint,
    /// Scalar decoding failed.
    #[error("scalar decoding failed")]
    InvalidScalar,
    /// Hex decoding failed.
    #[error("hex decoding failed: {0}")]
    HexError(String),
}

/// Create a Schnorr proof of knowledge of the discrete log of `public`.
pub fn prove(secret: &Scalar, public: &AffinePoint, message: &[u8]) -> SchnorrProof {
    use p256::elliptic_curve::Field;
    let mut k_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut k_bytes);
    let k_fb = p256::FieldBytes::from(k_bytes);
    let k_ct = Scalar::from_repr(k_fb);
    let k = Option::<Scalar>::from(k_ct).unwrap_or_else(|| Scalar::random(&mut OsRng));

    let r_point = ProjectivePoint::GENERATOR * k;
    let r_affine = r_point.to_affine();

    let c = fiat_shamir_challenge(public, &r_affine, message);
    let z = k + secret * &c;

    let r_encoded = r_affine.to_encoded_point(true);
    let z_bytes: [u8; 32] = z.to_repr().into();

    SchnorrProof {
        r_hex: hex::encode(r_encoded.as_bytes()),
        z_hex: hex::encode(z_bytes),
    }
}

/// Verify a Schnorr proof.
pub fn verify(
    proof: &SchnorrProof,
    public: &AffinePoint,
    message: &[u8],
) -> Result<bool, SchnorrError> {
    let r_bytes = hex::decode(&proof.r_hex).map_err(|e| SchnorrError::HexError(e.to_string()))?;
    let r_point = decode_point(&r_bytes)?;
    let z_bytes = hex::decode(&proof.z_hex).map_err(|e| SchnorrError::HexError(e.to_string()))?;
    if z_bytes.len() != 32 {
        return Err(SchnorrError::InvalidScalar);
    }
    let z_arr: [u8; 32] = z_bytes.as_slice().try_into().unwrap();
    let z_scalar = decode_scalar(&z_arr)?;

    let c = fiat_shamir_challenge(public, &r_point, message);

    let lhs = ProjectivePoint::GENERATOR * z_scalar;
    let rhs = ProjectivePoint::from(r_point) + ProjectivePoint::from(*public) * c;

    Ok(lhs == rhs)
}

fn fiat_shamir_challenge(public: &AffinePoint, r: &AffinePoint, message: &[u8]) -> Scalar {
    let public_encoded = public.to_encoded_point(true);
    let r_encoded = r.to_encoded_point(true);

    let mut hasher = Sha256::new();
    hasher.update(b"confium-schnorr-v1");
    hasher.update(public_encoded.as_bytes());
    hasher.update(r_encoded.as_bytes());
    hasher.update(message);
    let hash = hasher.finalize();

    let fb = p256::FieldBytes::from(hash);
    let ct = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

fn decode_point(bytes: &[u8]) -> Result<AffinePoint, SchnorrError> {
    let encoded = p256::EncodedPoint::from_bytes(bytes).map_err(|_| SchnorrError::InvalidPoint)?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(SchnorrError::InvalidPoint)
}

fn decode_scalar(bytes: &[u8; 32]) -> Result<Scalar, SchnorrError> {
    let fb = p256::FieldBytes::from(*bytes);
    let ct = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).ok_or(SchnorrError::InvalidScalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Field;

    fn random_keypair() -> (Scalar, AffinePoint) {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let fb = p256::FieldBytes::from(buf);
        let ct = Scalar::from_repr(fb);
        let secret = Option::<Scalar>::from(ct).unwrap_or_else(|| Scalar::random(&mut OsRng));
        let public = (ProjectivePoint::GENERATOR * &secret).to_affine();
        (secret, public)
    }

    #[test]
    fn valid_proof_verifies() {
        let (secret, public) = random_keypair();
        let proof = prove(&secret, &public, b"test message");
        assert!(verify(&proof, &public, b"test message").unwrap());
    }

    #[test]
    fn wrong_public_key_rejected() {
        let (secret, correct_public) = random_keypair();
        let (_, wrong_public) = random_keypair();
        let proof = prove(&secret, &correct_public, b"msg");
        assert!(verify(&proof, &correct_public, b"msg").unwrap());
        assert!(!verify(&proof, &wrong_public, b"msg").unwrap());
    }

    #[test]
    fn different_messages_produce_different_proofs() {
        let (secret, public) = random_keypair();
        let p1 = prove(&secret, &public, b"message A");
        let p2 = prove(&secret, &public, b"message B");
        assert_ne!(p1.r_hex, p2.r_hex);
    }

    #[test]
    fn tampered_z_rejected() {
        let (secret, public) = random_keypair();
        let mut proof = prove(&secret, &public, b"msg");
        let mut z_bytes = hex::decode(&proof.z_hex).unwrap();
        z_bytes[0] ^= 0xFF;
        proof.z_hex = hex::encode(&z_bytes);
        assert!(!verify(&proof, &public, b"msg").unwrap());
    }

    #[test]
    fn proof_serializes() {
        let (secret, public) = random_keypair();
        let proof = prove(&secret, &public, b"msg");
        let json = serde_json::to_string(&proof).unwrap();
        let recovered: SchnorrProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, recovered);
    }

    #[test]
    fn empty_message_works() {
        let (secret, public) = random_keypair();
        let proof = prove(&secret, &public, b"");
        assert!(verify(&proof, &public, b"").unwrap());
    }

    #[test]
    fn proof_is_non_deterministic() {
        let (secret, public) = random_keypair();
        let p1 = prove(&secret, &public, b"same message");
        let p2 = prove(&secret, &public, b"same message");
        assert_ne!(p1.r_hex, p2.r_hex);
        assert!(verify(&p1, &public, b"same message").unwrap());
        assert!(verify(&p2, &public, b"same message").unwrap());
    }
}
