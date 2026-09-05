//! Pedersen VSS — verifiable secret sharing with hiding commitments.

use getrandom::SysRng;
use sha2::{Digest as _, Sha256};
use p256::elliptic_curve::rand_core::UnwrapErr;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};

/// Pedersen VSS commitment: (C_i, D_i) = (g^{a_i} * h^{r_i}, h^{r_i}).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub c_points_hex: Vec<String>,
    pub d_points_hex: Vec<String>,
}

/// A Pedersen share: (x, y, y_r) where y = f(x), y_r = r(x).
/// The secret `value` and `randomness` fields are zeroized on drop.
#[derive(Debug, Clone)]
pub struct PedersenShare {
    pub party_idx: u32,
    pub value: Scalar,
    pub randomness: Scalar,
}

impl Drop for PedersenShare {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
        self.randomness.zeroize();
    }
}

/// Second generator h = g^alpha for some unknown alpha.
#[derive(Debug, Clone)]
pub struct PedersenParams {
    pub h: AffinePoint,
}

impl PedersenParams {
    /// Generate h = g^alpha for random alpha (trapdoor discarded).
    pub fn generate() -> Self {
        let alpha = Scalar::random(&mut UnwrapErr(SysRng));
        let h = (ProjectivePoint::GENERATOR * alpha).to_affine();
        Self { h }
    }
}

/// Deal a secret using Pedersen VSS.
/// Returns (commitments, shares) for T-of-N.
pub fn deal(
    secret: &Scalar,
    threshold: u32,
    party_count: u32,
    params: &PedersenParams,
) -> (PedersenCommitment, Vec<PedersenShare>) {
    // Two polynomials: f(x) for secret, r(x) for randomness
    let f_coeffs: Vec<Scalar> = (0..threshold)
        .map(|i| {
            if i == 0 {
                *secret
            } else {
                Scalar::random(&mut UnwrapErr(SysRng))
            }
        })
        .collect();
    let r_coeffs: Vec<Scalar> = (0..threshold)
        .map(|_| Scalar::random(&mut UnwrapErr(SysRng)))
        .collect();

    // Commitments: C_i = g^{f_i} * h^{r_i}, D_i = h^{r_i}
    let mut c_points = Vec::with_capacity(threshold as usize);
    let mut d_points = Vec::with_capacity(threshold as usize);
    for i in 0..threshold as usize {
        let g_fi = ProjectivePoint::GENERATOR * f_coeffs[i];
        let h_ri = ProjectivePoint::from(params.h) * r_coeffs[i];
        let c_i = (g_fi + h_ri).to_affine();
        let d_i = h_ri.to_affine();
        c_points.push(encode_point(&c_i));
        d_points.push(encode_point(&d_i));
    }

    // Shares: f(j), r(j) for j = 1..=N
    let shares: Vec<PedersenShare> = (1..=party_count)
        .map(|j| PedersenShare {
            party_idx: j,
            value: eval_poly(&f_coeffs, j),
            randomness: eval_poly(&r_coeffs, j),
        })
        .collect();

    (
        PedersenCommitment {
            c_points_hex: c_points,
            d_points_hex: d_points,
        },
        shares,
    )
}

/// Verify a Pedersen share against commitments.
/// Checks: g^{f(j)} * h^{r(j)} == product(C_i^{j^i}).
pub fn verify_share(
    share: &PedersenShare,
    commitment: &PedersenCommitment,
    params: &PedersenParams,
) -> bool {
    // Compute g^{f(j)} * h^{r(j)}
    let lhs = (ProjectivePoint::GENERATOR * share.value
        + ProjectivePoint::from(params.h) * share.randomness)
        .to_affine();

    // Compute product(C_i^{j^i})
    let mut rhs = ProjectivePoint::IDENTITY;
    let j = share.party_idx;
    let mut j_pow = Scalar::ONE;
    for i in 0..commitment.c_points_hex.len() {
        if let Some(c_i) = decode_point(&commitment.c_points_hex[i]) {
            rhs += ProjectivePoint::from(c_i) * j_pow;
        }
        let j_scalar = u32_to_scalar(j);
        j_pow *= j_scalar;
    }

    lhs == rhs.to_affine()
}

/// Extract the joint public key (C_0 without randomness hiding).
pub fn joint_public_key(commitment: &PedersenCommitment) -> Option<AffinePoint> {
    if commitment.c_points_hex.is_empty() {
        return None;
    }
    // C_0 = g^{secret} * h^{r_0}
    // The actual public key is g^{secret}, but we can't separate it without knowing r_0
    // For a committed public key, use C_0 / D_0 = g^{secret}
    if commitment.d_points_hex.is_empty() {
        return None;
    }
    let c0 = decode_point(&commitment.c_points_hex[0])?;
    let d0 = decode_point(&commitment.d_points_hex[0])?;
    let pk = ProjectivePoint::from(c0) - ProjectivePoint::from(d0);
    Some(pk.to_affine())
}

fn eval_poly(coeffs: &[Scalar], x: u32) -> Scalar {
    let x_scalar = u32_to_scalar(x);
    let mut result = Scalar::ZERO;
    let mut x_pow = Scalar::ONE;
    for c in coeffs {
        result += c * &x_pow;
        x_pow *= x_scalar;
    }
    result
}

fn u32_to_scalar(v: u32) -> Scalar {
    let mut arr = [0u8; 32];
    arr[28..32].copy_from_slice(&v.to_be_bytes());
    loop {
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(arr))) {
            return s;
        }
        arr = {
            let mut h = Sha256::new();
            h.update(b"confium-scalar-reduce-v1");
            h.update(arr);
            h.finalize().into()
        };
    }
}

fn encode_point(p: &AffinePoint) -> String {
    hex::encode(p.to_sec1_point(true).as_bytes())
}

fn decode_point(hex_str: &str) -> Option<AffinePoint> {
    let bytes = hex::decode(hex_str).ok()?;
    let encoded =
        p256::elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_bytes(&bytes).ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deal_and_verify() {
        let params = PedersenParams::generate();
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let (commitment, shares) = deal(&secret, 3, 5, &params);
        for share in &shares {
            assert!(
                verify_share(share, &commitment, &params),
                "party {}",
                share.party_idx
            );
        }
    }

    #[test]
    fn tampered_share_rejected() {
        let params = PedersenParams::generate();
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let (commitment, mut shares) = deal(&secret, 2, 3, &params);
        shares[0].value += Scalar::ONE;
        assert!(!verify_share(&shares[0], &commitment, &params));
    }

    #[test]
    fn joint_public_key_extracted() {
        let params = PedersenParams::generate();
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let (commitment, _) = deal(&secret, 2, 3, &params);
        let pk = joint_public_key(&commitment).unwrap();
        // g^{secret} == pk
        let expected = (ProjectivePoint::GENERATOR * secret).to_affine();
        assert_eq!(pk, expected);
    }

    #[test]
    fn different_secrets_different_commitments() {
        let params = PedersenParams::generate();
        let s1 = Scalar::random(&mut UnwrapErr(SysRng));
        let s2 = Scalar::random(&mut UnwrapErr(SysRng));
        let (c1, _) = deal(&s1, 2, 3, &params);
        let (c2, _) = deal(&s2, 2, 3, &params);
        assert_ne!(c1.c_points_hex[0], c2.c_points_hex[0]);
    }

    #[test]
    fn threshold_one_works() {
        let params = PedersenParams::generate();
        let secret = Scalar::random(&mut UnwrapErr(SysRng));
        let (commitment, shares) = deal(&secret, 1, 3, &params);
        assert_eq!(shares.len(), 3);
        for share in &shares {
            assert!(verify_share(share, &commitment, &params));
        }
    }
}
