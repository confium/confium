//! Verifiable Secret Sharing (VSS) — Feldman VSS over P-256.
//!
//! Allows shareholders to verify their share is valid (lies on the
//! committed polynomial) without revealing it. Used by CMP20, FROST,
//! and GG18 internally.
//!
//! ## Feldman VSS
//!
//! The dealer picks a random polynomial `f(x) = a_0 + a_1*x + ... + a_{T-1}*x^{T-1}`
//! where `a_0` is the secret. They publish commitments `C_i = g^{a_i}`
//! for each coefficient. Each shareholder with index `j` receives
//! share `f(j)`. They verify: `g^{f(j)} == product(C_i^{j^i})`.

use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, ProjectivePoint, Scalar};

/// Public commitments from a Feldman VSS deal.
///
/// `C_0 = g^{a_0}` is the joint public key. The remaining commitments
/// `C_1...C_{T-1}` allow shareholders to verify their shares.
#[derive(Debug, Clone)]
pub struct VssCommitment {
    /// Commitment to each polynomial coefficient: `C_i = g^{a_i}`.
    pub commitments: Vec<AffinePoint>,
}

impl VssCommitment {
    /// Create a new VSS commitment from coefficient commitments.
    pub fn new(commitments: Vec<AffinePoint>) -> Self {
        Self { commitments }
    }

    /// The threshold T (number of shares needed to reconstruct).
    pub fn threshold(&self) -> usize {
        self.commitments.len()
    }

    /// The joint public key: `C_0 = g^{secret}`.
    pub fn joint_public_key(&self) -> AffinePoint {
        self.commitments[0]
    }

    /// Verify that a share `(party_idx, share)` is consistent with
    /// the committed polynomial.
    ///
    /// Checks: `g^{share} == product_i(C_i^{party_idx^i})`
    pub fn verify_share(&self, party_idx_1based: u64, share: Scalar) -> bool {
        let x = u64_to_scalar(party_idx_1based);
        let lhs = ProjectivePoint::GENERATOR * share;

        let mut rhs = ProjectivePoint::IDENTITY;
        let mut x_pow = Scalar::ONE;
        for c in &self.commitments {
            let c_proj = ProjectivePoint::from(*c);
            rhs += c_proj * x_pow;
            x_pow = x_pow * x;
        }
        lhs == rhs
    }

    /// Encode commitments as concatenated SEC1 compressed points.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.commitments.len() * 33);
        for c in &self.commitments {
            let encoded = c.to_encoded_point(true);
            out.extend_from_slice(encoded.as_bytes());
        }
        out
    }

    /// Decode commitments from concatenated SEC1 compressed points.
    /// Each point is 33 bytes. Returns `None` if any point is invalid.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() % 33 != 0 {
            return None;
        }
        let mut commitments = Vec::with_capacity(bytes.len() / 33);
        for chunk in bytes.chunks_exact(33) {
            let point = p256::EncodedPoint::from_bytes(chunk).ok()?;
            let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&point))?;
            commitments.push(affine);
        }
        Some(Self { commitments })
    }
}

fn u64_to_scalar(v: u64) -> Scalar {
    let mut arr = [0u8; 32];
    arr[24..32].copy_from_slice(&v.to_be_bytes());
    let fb = p256::FieldBytes::from(arr);
    let ct = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_scalar() -> Scalar {
        use p256::elliptic_curve::Field;
        use p256::elliptic_curve::rand_core::OsRng;
        Scalar::random(&mut OsRng)
    }

    fn make_commitment_for_polynomial(coeffs: &[Scalar]) -> VssCommitment {
        let commitments: Vec<AffinePoint> = coeffs
            .iter()
            .map(|c| (ProjectivePoint::GENERATOR * c).to_affine())
            .collect();
        VssCommitment::new(commitments)
    }

    fn evaluate_polynomial(coeffs: &[Scalar], x: u64) -> Scalar {
        let x_scalar = u64_to_scalar(x);
        let mut result = Scalar::ZERO;
        let mut x_pow = Scalar::ONE;
        for c in coeffs {
            result = result + c * &x_pow;
            x_pow = x_pow * &x_scalar;
        }
        result
    }

    #[test]
    fn valid_share_verifies() {
        let coeffs: Vec<Scalar> = (0..3).map(|_| random_scalar()).collect();
        let commitment = make_commitment_for_polynomial(&coeffs);
        let share = evaluate_polynomial(&coeffs, 1);
        assert!(commitment.verify_share(1, share));
    }

    #[test]
    fn invalid_share_rejected() {
        let coeffs: Vec<Scalar> = (0..3).map(|_| random_scalar()).collect();
        let commitment = make_commitment_for_polynomial(&coeffs);
        let bad_share = random_scalar();
        assert!(!commitment.verify_share(1, bad_share));
    }

    #[test]
    fn multiple_party_indices_verify() {
        let coeffs: Vec<Scalar> = (0..4).map(|_| random_scalar()).collect();
        let commitment = make_commitment_for_polynomial(&coeffs);
        for party_idx in 1..=5u64 {
            let share = evaluate_polynomial(&coeffs, party_idx);
            assert!(
                commitment.verify_share(party_idx, share),
                "party {party_idx} should verify"
            );
        }
    }

    #[test]
    fn joint_public_key_is_first_commitment() {
        let coeffs: Vec<Scalar> = (0..3).map(|_| random_scalar()).collect();
        let commitment = make_commitment_for_polynomial(&coeffs);
        let expected_pk = (ProjectivePoint::GENERATOR * coeffs[0]).to_affine();
        assert_eq!(commitment.joint_public_key(), expected_pk);
    }

    #[test]
    fn threshold_is_commitment_count() {
        let commitment = make_commitment_for_polynomial(&[random_scalar(); 5]);
        assert_eq!(commitment.threshold(), 5);
    }

    #[test]
    fn encode_decode_round_trips() {
        let coeffs: Vec<Scalar> = (0..3).map(|_| random_scalar()).collect();
        let commitment = make_commitment_for_polynomial(&coeffs);
        let encoded = commitment.encode();
        assert_eq!(encoded.len(), 3 * 33);

        let decoded = VssCommitment::decode(&encoded).unwrap();
        assert_eq!(decoded.commitments.len(), commitment.commitments.len());
        for (a, b) in commitment
            .commitments
            .iter()
            .zip(decoded.commitments.iter())
        {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(VssCommitment::decode(&[0; 10]).is_none());
        assert!(VssCommitment::decode(&[0; 34]).is_none());
    }

    #[test]
    fn decode_rejects_invalid_point() {
        assert!(VssCommitment::decode(&[0; 33]).is_none());
    }
}
