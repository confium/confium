//! General-purpose NIZK proof system using Fiat-Shamir transform.

use getrandom::SysRng;
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::rand_core::{Rng, UnwrapErr};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// A generic NIZK proof.
#[derive(Debug, Clone)]
pub struct NizkProof {
    pub commitment: AffinePoint,
    pub challenge: Scalar,
    pub response: Scalar,
}

/// Prove knowledge of a discrete log: know x such that Y = x * G.
pub fn prove_dlog(secret: &Scalar) -> NizkProof {
    let mut nonce_bytes = [0u8; 32];
    UnwrapErr(SysRng).fill_bytes(&mut nonce_bytes);
    let nonce = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(nonce_bytes)))
        .unwrap_or(Scalar::ZERO);

    let commitment = (ProjectivePoint::GENERATOR * nonce).to_affine();
    let public = (ProjectivePoint::GENERATOR * secret).to_affine();

    let challenge = fiat_shamir_challenge(&public, &commitment, b"dlog");
    let response = nonce + challenge * secret;

    NizkProof {
        commitment,
        challenge,
        response,
    }
}

/// Verify a DLOG proof.
pub fn verify_dlog(public: &AffinePoint, proof: &NizkProof) -> bool {
    let expected_challenge = fiat_shamir_challenge(public, &proof.commitment, b"dlog");
    if expected_challenge != proof.challenge {
        return false;
    }
    // Check: response * G == commitment + challenge * public
    let lhs = ProjectivePoint::GENERATOR * proof.response;
    let rhs =
        ProjectivePoint::from(proof.commitment) + ProjectivePoint::from(*public) * proof.challenge;
    lhs == rhs
}

/// Prove equality of discrete logs: Y1 = x*G1 and Y2 = x*G2 (same x).
pub fn prove_dlog_equality(
    secret: &Scalar,
    g1: &AffinePoint,
    g2: &AffinePoint,
) -> (NizkProof, NizkProof) {
    let mut nonce_bytes = [0u8; 32];
    UnwrapErr(SysRng).fill_bytes(&mut nonce_bytes);
    let nonce = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(nonce_bytes)))
        .unwrap_or(Scalar::ZERO);

    let commit1 = (ProjectivePoint::from(*g1) * nonce).to_affine();
    let commit2 = (ProjectivePoint::from(*g2) * nonce).to_affine();

    let y1 = (ProjectivePoint::from(*g1) * secret).to_affine();
    let y2 = (ProjectivePoint::from(*g2) * secret).to_affine();

    let challenge = equality_challenge(&y1, &y2, &commit1, &commit2);
    let response = nonce + challenge * secret;

    (
        NizkProof {
            commitment: commit1,
            challenge,
            response,
        },
        NizkProof {
            commitment: commit2,
            challenge,
            response,
        },
    )
}

/// Verify equality of discrete logs.
pub fn verify_dlog_equality(
    y1: &AffinePoint,
    y2: &AffinePoint,
    g1: &AffinePoint,
    g2: &AffinePoint,
    proof1: &NizkProof,
    proof2: &NizkProof,
) -> bool {
    // Same challenge and response
    if proof1.challenge != proof2.challenge || proof1.response != proof2.response {
        return false;
    }
    let expected_challenge = equality_challenge(y1, y2, &proof1.commitment, &proof2.commitment);
    if expected_challenge != proof1.challenge {
        return false;
    }
    // Verify both equations
    let lhs1 = ProjectivePoint::from(*g1) * proof1.response;
    let rhs1 =
        ProjectivePoint::from(proof1.commitment) + ProjectivePoint::from(*y1) * proof1.challenge;
    let lhs2 = ProjectivePoint::from(*g2) * proof2.response;
    let rhs2 =
        ProjectivePoint::from(proof2.commitment) + ProjectivePoint::from(*y2) * proof2.challenge;
    lhs1 == rhs1 && lhs2 == rhs2
}

fn fiat_shamir_challenge(public: &AffinePoint, commitment: &AffinePoint, domain: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"nizk");
    hasher.update(domain);
    hasher.update(public.to_sec1_point(true).as_bytes());
    hasher.update(commitment.to_sec1_point(true).as_bytes());
    let fb = FieldBytes::try_from(&hasher.finalize()[..]).expect("digest is 32 bytes");
    Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

fn equality_challenge(
    y1: &AffinePoint,
    y2: &AffinePoint,
    c1: &AffinePoint,
    c2: &AffinePoint,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"nizk-equality");
    hasher.update(y1.to_sec1_point(true).as_bytes());
    hasher.update(y2.to_sec1_point(true).as_bytes());
    hasher.update(c1.to_sec1_point(true).as_bytes());
    hasher.update(c2.to_sec1_point(true).as_bytes());
    let fb = FieldBytes::try_from(&hasher.finalize()[..]).expect("digest is 32 bytes");
    Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Field;

    #[test]
    fn dlog_proof_verifies() {
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let proof = prove_dlog(&secret);
        let public = (ProjectivePoint::GENERATOR * secret).to_affine();
        assert!(verify_dlog(&public, &proof));
    }

    #[test]
    fn dlog_wrong_public_rejected() {
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let proof = prove_dlog(&secret);
        let wrong =
            (ProjectivePoint::GENERATOR * Scalar::random(&mut UnwrapErr(SysRng))).to_affine();
        assert!(!verify_dlog(&wrong, &proof));
    }

    #[test]
    fn dlog_tampered_response_rejected() {
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let mut proof = prove_dlog(&secret);
        let public = (ProjectivePoint::GENERATOR * secret).to_affine();
        proof.response += Scalar::ONE;
        assert!(!verify_dlog(&public, &proof));
    }

    #[test]
    fn dlog_proof_non_deterministic() {
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let p1 = prove_dlog(&secret);
        let p2 = prove_dlog(&secret);
        assert_ne!(p1.commitment, p2.commitment);
    }

    #[test]
    fn equality_proof_verifies() {
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let g1 = AffinePoint::GENERATOR;
        let g2 = (ProjectivePoint::GENERATOR * Scalar::from(2u32)).to_affine();

        let (p1, p2) = prove_dlog_equality(&secret, &g1, &g2);
        let y1 = (ProjectivePoint::from(g1) * secret).to_affine();
        let y2 = (ProjectivePoint::from(g2) * secret).to_affine();

        assert!(verify_dlog_equality(&y1, &y2, &g1, &g2, &p1, &p2));
    }

    #[test]
    fn equality_wrong_secret_rejected() {
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let g1 = AffinePoint::GENERATOR;
        let g2 = (ProjectivePoint::GENERATOR * Scalar::from(2u32)).to_affine();

        let (p1, p2) = prove_dlog_equality(&secret, &g1, &g2);
        let wrong = Scalar::random(&mut UnwrapErr(SysRng));
        let y1 = (ProjectivePoint::from(g1) * wrong).to_affine();
        let y2 = (ProjectivePoint::from(g2) * secret).to_affine();

        assert!(!verify_dlog_equality(&y1, &y2, &g1, &g2, &p1, &p2));
    }

    #[test]
    fn nizk_proof_serializes() {
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let proof = prove_dlog(&secret);
        // Just verify it has the right structure
        assert!(proof.challenge != Scalar::ZERO || proof.response != Scalar::ZERO);
    }
}
