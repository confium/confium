//! Feldman verifiable secret sharing over P-256.
//!
//! A dealer samples a degree-`T-1` polynomial
//! `f(x) = a_0 + a_1 x + ... + a_{T-1} x^{T-1}` with `a_0 = secret`,
//! privately sends each party `i` the evaluation `y_i = f(i)`, and
//! broadcasts Feldman commitments `C_j = g^{a_j}`. Recipients verify
//! `g^{y_i} == \prod_j C_j^{i^j}` without learning the coefficients.
//! `C_0 = g^{secret}` is the public key for the shared secret.
//!
//! CMP20's non-interactive key generation folds the commitment
//! broadcast and the per-peer share delivery into a single round: each
//! party broadcasts its full commitment list and bundles every peer's
//! evaluation into the same message, so no second round is needed.

use elliptic_curve::Field;
use elliptic_curve::rand_core::CryptoRng;
use elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, ProjectivePoint, Scalar};

/// One dealer's Feldman VSS output.
#[derive(Clone, Debug)]
pub struct FeldmanVss {
    pub commitments: Vec<AffinePoint>,
    pub shares: Vec<Scalar>,
    pub secret: Scalar,
}

impl FeldmanVss {
    pub fn deal(rng: &mut impl CryptoRng, n: usize, t: usize) -> Self {
        debug_assert!(t >= 1 && t <= n);
        let mut coeffs: Vec<Scalar> = (0..t).map(|_| Scalar::random(&mut *rng)).collect();
        let secret = coeffs[0];
        let g = ProjectivePoint::GENERATOR;
        let commitments: Vec<AffinePoint> = coeffs.iter().map(|a| (g * a).to_affine()).collect();
        let shares: Vec<Scalar> = (1..=n as u64)
            .map(|i| {
                let x = Scalar::from(i);
                let mut acc = Scalar::ZERO;
                for &a in coeffs.iter().rev() {
                    acc = acc * x + a;
                }
                acc
            })
            .collect();
        coeffs.fill(Scalar::ZERO);
        FeldmanVss {
            commitments,
            shares,
            secret,
        }
    }

    pub fn verify_share(commitments: &[AffinePoint], party_idx_1based: u64, share: Scalar) -> bool {
        if commitments.is_empty() {
            return false;
        }
        let g = ProjectivePoint::GENERATOR;
        let lhs = g * share;
        let i_scalar = Scalar::from(party_idx_1based);
        let mut rhs = ProjectivePoint::IDENTITY;
        let mut i_pow = Scalar::ONE;
        for c in commitments {
            rhs += ProjectivePoint::from(*c) * i_pow;
            i_pow *= i_scalar;
        }
        lhs == rhs
    }

    pub fn encode_commitments(commitments: &[AffinePoint]) -> Vec<u8> {
        let mut out = Vec::with_capacity(commitments.len() * 33);
        for c in commitments {
            out.extend_from_slice(c.to_sec1_point(true).as_bytes());
        }
        out
    }

    pub fn decode_commitments(bytes: &[u8]) -> Option<Vec<AffinePoint>> {
        if bytes.len() % 33 != 0 {
            return None;
        }
        use elliptic_curve::point::AffineCoordinates;
        use elliptic_curve::sec1::FromSec1Point;
        use p256::NistP256;
        let mut out = Vec::with_capacity(bytes.len() / 33);
        for chunk in bytes.chunks_exact(33) {
            let enc = elliptic_curve::sec1::Sec1Point::<NistP256>::from_bytes(chunk).ok()?;
            let pt: AffinePoint = Option::from(AffinePoint::from_sec1_point(&enc))?;
            let _ = pt.x();
            out.push(pt);
        }
        Some(out)
    }

    pub fn public_key(&self) -> AffinePoint {
        self.commitments[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::rand_core::UnwrapErr;
    use getrandom::SysRng;

    #[test]
    fn feldman_share_verifies() {
        let vss = FeldmanVss::deal(&mut UnwrapErr(SysRng), 5, 3);
        for (i, &share) in vss.shares.iter().enumerate() {
            assert!(
                FeldmanVss::verify_share(&vss.commitments, (i + 1) as u64, share),
                "share for party {} must verify",
                i + 1
            );
        }
    }

    #[test]
    fn feldman_rejects_tampered_share() {
        let vss = FeldmanVss::deal(&mut UnwrapErr(SysRng), 5, 3);
        let bad_share = vss.shares[0] + Scalar::from(1u64);
        assert!(!FeldmanVss::verify_share(&vss.commitments, 1, bad_share));
    }

    #[test]
    fn feldman_commitments_round_trip() {
        let vss = FeldmanVss::deal(&mut UnwrapErr(SysRng), 5, 3);
        let enc = FeldmanVss::encode_commitments(&vss.commitments);
        let dec = FeldmanVss::decode_commitments(&enc).expect("decode");
        assert_eq!(dec.len(), vss.commitments.len());
        for (a, b) in vss.commitments.iter().zip(dec.iter()) {
            let ab = a.to_sec1_point(true);
            let bb = b.to_sec1_point(true);
            assert_eq!(ab.as_bytes(), bb.as_bytes());
        }
    }

    #[test]
    fn feldman_decode_rejects_garbage() {
        assert!(FeldmanVss::decode_commitments(&[0u8; 10]).is_none());
    }
}
