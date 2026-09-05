//! DKG coordinator protocol — distributed key generation.
//!
//! Each party contributes randomness to generate a shared keypair
//! without any single party knowing the full secret.

use getrandom::SysRng;
use p256::elliptic_curve::rand_core::UnwrapErr;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

/// A DKG contribution from one party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgContribution {
    pub party_idx: u32,
    /// Shamir share for each other party.
    pub shares: HashMap<u32, String>,
    /// VSS commitment (SEC1 compressed, hex).
    pub commitment_hex: String,
}

/// DKG session state.
#[derive(Debug)]
pub struct DkgSession {
    pub threshold: u32,
    pub party_count: u32,
    pub contributions: HashMap<u32, DkgContribution>,
}

impl DkgSession {
    pub fn new(threshold: u32, party_count: u32) -> Self {
        Self {
            threshold,
            party_count,
            contributions: HashMap::new(),
        }
    }

    pub fn submit(&mut self, contrib: DkgContribution) -> Result<(), String> {
        if contrib.party_idx == 0 || contrib.party_idx > self.party_count {
            return Err("invalid party index".into());
        }
        if self.contributions.contains_key(&contrib.party_idx) {
            return Err("duplicate contribution".into());
        }
        self.contributions.insert(contrib.party_idx, contrib);
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.contributions.len() == self.party_count as usize
    }

    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    pub fn missing_parties(&self) -> Vec<u32> {
        (1..=self.party_count)
            .filter(|i| !self.contributions.contains_key(i))
            .collect()
    }
}

/// Generate a DKG contribution: polynomial shares for all parties.
pub fn generate_contribution(
    party_idx: u32,
    threshold: u32,
    party_count: u32,
) -> (DkgContribution, Scalar) {
    // Random polynomial: f(0) = secret, f(x) for x in 1..N
    let coeffs: Vec<Scalar> = (0..threshold)
        .map(|_| Scalar::random(&mut UnwrapErr(SysRng)))
        .collect();

    let secret = coeffs[0];

    // Compute shares for each party: f(i)
    let mut shares = HashMap::new();
    for i in 1..=party_count {
        let eval = eval_polynomial(&coeffs, i);
        let bytes: [u8; 32] = eval.to_repr().into();
        shares.insert(i, hex::encode(bytes));
    }

    // VSS commitment: g^{coeffs[0]}
    let commitment = (ProjectivePoint::GENERATOR * secret).to_affine();
    use p256::elliptic_curve::sec1::ToSec1Point;
    let commitment_hex = hex::encode(commitment.to_sec1_point(true).as_bytes());

    (
        DkgContribution {
            party_idx,
            shares,
            commitment_hex,
        },
        secret,
    )
}

/// Compute party i's aggregate share from all contributions.
pub fn compute_aggregate_share(session: &DkgSession, party_idx: u32) -> Result<Scalar, String> {
    if !session.is_complete() {
        return Err("DKG not complete".into());
    }
    let mut aggregate = Scalar::ZERO;
    for contrib in session.contributions.values() {
        let share_hex = contrib
            .shares
            .get(&party_idx)
            .ok_or_else(|| format!("missing share for party {party_idx}"))?;
        let bytes = hex::decode(share_hex).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("invalid share length".into());
        }
        let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
        let fb = FieldBytes::from(arr);
        let share = Option::<Scalar>::from(Scalar::from_repr(fb))
            .ok_or_else(|| "invalid scalar".to_string())?;
        aggregate += share;
    }
    Ok(aggregate)
}

/// Compute the joint public key from all VSS commitments.
pub fn compute_joint_public_key(session: &DkgSession) -> Result<AffinePoint, String> {
    if !session.is_complete() {
        return Err("DKG not complete".into());
    }
    use p256::elliptic_curve::sec1::FromSec1Point;
    let mut sum = ProjectivePoint::IDENTITY;
    for contrib in session.contributions.values() {
        let bytes = hex::decode(&contrib.commitment_hex).map_err(|e| e.to_string())?;
        let encoded = p256::elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_bytes(&bytes)
            .map_err(|e| e.to_string())?;
        let point = Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&encoded))
            .ok_or_else(|| "invalid commitment point".to_string())?;
        sum += ProjectivePoint::from(point);
    }
    Ok(sum.to_affine())
}

fn eval_polynomial(coeffs: &[Scalar], x: u32) -> Scalar {
    let x_scalar = u32_to_scalar(x);
    let mut result = Scalar::ZERO;
    let mut x_pow = Scalar::ONE;
    for c in coeffs {
        result += c * &x_pow;
        x_pow *= x_scalar;
    }
    result
}

/// Reduce 32 bytes to a scalar by rejection sampling with re-hash;
/// never falls back to a constant.
fn reduce_to_scalar(mut bytes: [u8; 32]) -> Scalar {
    loop {
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(bytes))) {
            return s;
        }
        let mut h = Sha256::new();
        h.update(b"confium-scalar-reduce-v1");
        h.update(bytes);
        bytes = h.finalize().into();
    }
}

fn u32_to_scalar(v: u32) -> Scalar {
    // Garbage-in-garbage-out on zero input; protocol callers pass
    // non-zero scalars (sweep ledger: SEC-audit-notes).
    let mut arr = [0u8; 32];
    arr[28..32].copy_from_slice(&v.to_be_bytes());
    let fb = FieldBytes::from(arr);
    Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkg_session_starts_empty() {
        let session = DkgSession::new(2, 3);
        assert_eq!(session.contribution_count(), 0);
        assert!(!session.is_complete());
    }

    #[test]
    fn submit_contribution() {
        let mut session = DkgSession::new(2, 3);
        let (contrib, _) = generate_contribution(1, 2, 3);
        session.submit(contrib).unwrap();
        assert_eq!(session.contribution_count(), 1);
    }

    #[test]
    fn complete_when_all_contributed() {
        let mut session = DkgSession::new(2, 3);
        for i in 1..=3 {
            let (contrib, _) = generate_contribution(i, 2, 3);
            session.submit(contrib).unwrap();
        }
        assert!(session.is_complete());
    }

    #[test]
    fn duplicate_contribution_rejected() {
        let mut session = DkgSession::new(2, 3);
        let (c1, _) = generate_contribution(1, 2, 3);
        session.submit(c1).unwrap();
        let (c2, _) = generate_contribution(1, 2, 3);
        assert!(session.submit(c2).is_err());
    }

    #[test]
    fn aggregate_share_computed() {
        let mut session = DkgSession::new(2, 3);
        for i in 1..=3 {
            let (contrib, _) = generate_contribution(i, 2, 3);
            session.submit(contrib).unwrap();
        }
        let share = compute_aggregate_share(&session, 1).unwrap();
        assert!(share != Scalar::ZERO);
    }

    #[test]
    fn joint_public_key_computed() {
        let mut session = DkgSession::new(2, 3);
        for i in 1..=3 {
            let (contrib, _) = generate_contribution(i, 2, 3);
            session.submit(contrib).unwrap();
        }
        let pk = compute_joint_public_key(&session).unwrap();
        // Just verify it's not identity
        assert!(pk != AffinePoint::IDENTITY);
    }

    #[test]
    fn missing_parties_listed() {
        let mut session = DkgSession::new(2, 5);
        let (c1, _) = generate_contribution(1, 2, 5);
        session.submit(c1).unwrap();
        let (c3, _) = generate_contribution(3, 2, 5);
        session.submit(c3).unwrap();
        assert_eq!(session.missing_parties(), vec![2, 4, 5]);
    }

    #[test]
    fn contribution_has_shares_for_all_parties() {
        let (contrib, _) = generate_contribution(1, 2, 3);
        assert_eq!(contrib.shares.len(), 3);
        assert!(contrib.shares.contains_key(&1));
        assert!(contrib.shares.contains_key(&2));
        assert!(contrib.shares.contains_key(&3));
    }
}
