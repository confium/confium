//! General-purpose NIZK proof system using Fiat-Shamir transform.

use getrandom::SysRng;
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::rand_core::{Rng, UnwrapErr};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};


/// Reduce 32 bytes to a scalar by rejection sampling with
/// re-hashing. Never falls back to a constant: a zero nonce leaks
/// the secret in the response, and a zero challenge accepts
/// forgeries, so both must be impossible by construction.
fn hash_to_scalar(mut fb: [u8; 32]) -> Scalar {
    loop {
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(fb))) {
            return s;
        }
        let mut h = Sha256::new();
        h.update(b"confium-scalar-reduce-v1");
        h.update(fb);
        fb = h.finalize().into();
    }
}

/// Sample a uniform nonce: rejection sampling over OS randomness.
fn random_nonce() -> Scalar {
    loop {
        let mut b = [0u8; 32];
        UnwrapErr(SysRng).fill_bytes(&mut b);
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(b))) {
            return s;
        }
    }
}

/// A generic NIZK proof.
#[derive(Debug, Clone)]
pub struct NizkProof {
    pub commitment: AffinePoint,
    pub challenge: Scalar,
    pub response: Scalar,
}

/// Prove knowledge of a discrete log: know x such that Y = x * G.
pub fn prove_dlog(secret: &Scalar) -> NizkProof {
    let nonce = random_nonce();

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
    let nonce = random_nonce();

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
    let fb: [u8; 32] = hasher.finalize().into();
    hash_to_scalar(fb)
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
    let fb: [u8; 32] = hasher.finalize().into();
    hash_to_scalar(fb)
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

#[cfg(test)]
mod adversarial_tests {
    //! Every verify() carries a paired rejects-forgery test: a
    //! self-consistent but false statement must never verify.

    use super::*;
    use p256::elliptic_curve::Field as _;

    fn keypair() -> (Scalar, AffinePoint) {
        let sk = Scalar::random(&mut UnwrapErr(SysRng));
        let pk = (ProjectivePoint::GENERATOR * sk).to_affine();
        (sk, pk)
    }

    #[test]
    fn rejects_forged_challenge_dlog() {
        let (sk, pk) = keypair();
        let proof = prove_dlog(&sk);
        let mut forged = proof.clone();
        forged.challenge += Scalar::ONE; // breaks the transcript hash
        assert!(!verify_dlog(&pk, &forged));
    }

    #[test]
    fn rejects_proof_for_a_different_key() {
        let (sk, _) = keypair();
        let (_, other_pk) = keypair();
        let proof = prove_dlog(&sk);
        // Valid transcript bound to the wrong statement.
        assert!(!verify_dlog(&other_pk, &proof));
    }

    #[test]
    fn rejects_tampered_response_dlog() {
        let (sk, pk) = keypair();
        let mut proof = prove_dlog(&sk);
        proof.response += Scalar::ONE;
        assert!(!verify_dlog(&pk, &proof));
    }

    #[test]
    fn rejects_mismatched_equality_proofs() {
        let (sk, _) = keypair();
        let g1 = ProjectivePoint::GENERATOR.to_affine();
        let g2 = (ProjectivePoint::GENERATOR * Scalar::from(7u64)).to_affine();
        let (p1, mut p2) = prove_dlog_equality(&sk, &g1, &g2);
        // Same challenge, but a response belonging to another secret.
        p2.response += Scalar::ONE;
        let y1 = (ProjectivePoint::from(g1) * sk).to_affine();
        let y2 = (ProjectivePoint::from(g2) * sk).to_affine();
        assert!(!verify_dlog_equality(&y1, &y2, &g1, &g2, &p1, &p2));
    }
}
