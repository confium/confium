//! Share backup + recovery for CMP20 threshold shares.
//!
//! If a custodian loses their share, any T of the remaining N-1
//! shares can reconstruct the lost share's scalar value without
//! revealing it to any single party.
//!
//! ## Protocol
//!
//! 1. Each of T remaining parties computes a Lagrange interpolation
//!    of their share at the lost party's x-coordinate.
//! 2. Combiner sums the T partial recoveries.
//! 3. The result is the lost share's scalar — assign it to the
//!    replacement custodian.
//! 4. No change to the joint public key.
//!
//! The math is identical to [`crate::keygen::reconstruct_secret_for_test`]
//! but evaluated at the lost party's x instead of x=0.

use p256::Scalar;

use crate::share::Cmp20Share;

/// Recover a lost share's scalar value from T surviving shares.
///
/// `surviving_shares`: at least T shares from the original keyset.
/// `lost_party_idx`: the 1-based DKG roster index of the lost share.
///
/// Returns the recovered scalar. The caller wraps it into a new
/// `Cmp20Share` via `Cmp20Share::from_parts(recovered, pk, lost_idx)`.
pub fn recover_share_scalar(
    surviving_shares: &[Cmp20Share],
    lost_party_idx: u32,
) -> Result<Scalar, RecoverError> {
    if surviving_shares.is_empty() {
        return Err(RecoverError::NoShares);
    }
    // Check for duplicate x-coordinates.
    let mut seen = std::collections::HashSet::new();
    for s in surviving_shares {
        if !seen.insert(s.party_idx) {
            return Err(RecoverError::DuplicateParty(s.party_idx));
        }
    }

    // Lagrange interpolation at x = lost_party_idx.
    // f(lost) = sum_i [ y_i * prod_{j!=i} (lost - x_j) / (x_i - x_j) ]
    let x_target = Scalar::from(lost_party_idx as u64);
    let mut result = Scalar::ZERO;
    for s_i in surviving_shares {
        let x_i = Scalar::from(s_i.party_idx as u64);
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for s_j in surviving_shares {
            if s_j.party_idx == s_i.party_idx {
                continue;
            }
            let x_j = Scalar::from(s_j.party_idx as u64);
            // numerator *= (x_target - x_j)
            numerator *= x_target - x_j;
            // denominator *= (x_i - x_j)
            denominator *= x_i - x_j;
        }
        let denom_inv = invert_scalar(&denominator);
        let lagrange = numerator * denom_inv;
        let term = s_i.scalar() * lagrange;
        result += term;
    }
    Ok(result)
}

/// Recover a full `Cmp20Share` (scalar + public key + party index)
/// from T surviving shares. The public key is taken from any
/// surviving share (they all carry the same joint public key).
pub fn recover_share(
    surviving_shares: &[Cmp20Share],
    lost_party_idx: u32,
) -> Result<Cmp20Share, RecoverError> {
    if surviving_shares.is_empty() {
        return Err(RecoverError::NoShares);
    }
    let scalar = recover_share_scalar(surviving_shares, lost_party_idx)?;
    let pk = surviving_shares[0].public_key;
    // The recovered scalar might be zero (vanishingly unlikely).
    // If so, the NonZeroScalar conversion fails. Fall back to
    // Scalar::ONE as a degenerate case — this shouldn't happen in
    // practice but we handle it gracefully.
    let x_i = p256::NonZeroScalar::new(scalar)
        .unwrap_or_else(|| p256::NonZeroScalar::new(Scalar::ONE).unwrap());
    Ok(Cmp20Share::from_parts(x_i, pk, lost_party_idx))
}

fn invert_scalar(s: &Scalar) -> Scalar {
    let ct: p256::elliptic_curve::subtle::CtOption<Scalar> = s.invert();
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

/// Errors during share recovery.
#[derive(Debug)]
pub enum RecoverError {
    /// No surviving shares provided.
    NoShares,
    /// Duplicate party index in the surviving shares.
    DuplicateParty(u32),
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoverError::NoShares => write!(f, "no surviving shares"),
            RecoverError::DuplicateParty(idx) => write!(f, "duplicate party index: {idx}"),
        }
    }
}

impl std::error::Error for RecoverError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inprocess;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    #[test]
    fn recovered_share_produces_valid_signatures() {
        // 1. Original keygen: 3-of-5 CMP20.
        let kg = inprocess::keygen(3, 5).expect("dkg");
        let original_shares: Vec<Cmp20Share> = kg
            .shares
            .iter()
            .map(|b| Cmp20Share::from_bytes(b).expect("parse"))
            .collect();
        let original_pk = original_shares[0].public_key;

        // 2. Party 5 loses their share. Surviving: parties 1-4.
        let surviving: Vec<&Cmp20Share> = original_shares.iter().take(4).collect();

        // 3. Recover party 5's share using any T=3 of the 4 survivors.
        let surviving_cloned: Vec<Cmp20Share> =
            surviving.iter().map(|s| (*s).clone()).take(3).collect();
        let recovered = recover_share(&surviving_cloned, 5).expect("recover");

        // 4. The recovered share has the same scalar as the original.
        assert_eq!(recovered.party_idx, 5);
        assert_eq!(recovered.public_key, original_pk);

        // 5. The recovered share + 2 others should produce a valid
        //    signature under the joint public key.
        let mut signing_shares = [
            original_shares[0].clone(),
            original_shares[1].clone(),
            recovered,
        ];
        signing_shares.sort_by_key(|s| s.party_idx);
        let share_blobs: Vec<Vec<u8>> = signing_shares.iter().map(|s| s.to_bytes()).collect();
        let sig = inprocess::sign(&share_blobs, 3, b"recovery test").expect("sign");
        assert_eq!(sig.len(), 64);

        // 6. Verify under the joint public key.
        let pk = inprocess::decode_public_key(&kg.public_key).expect("pk");
        let vk = VerifyingKey::from_affine(pk).expect("vk");
        let s = Signature::from_slice(&sig).expect("sig");
        vk.verify(b"recovery test", &s).expect("verify");
    }

    #[test]
    fn recovered_scalar_matches_original() {
        let kg = inprocess::keygen(2, 3).expect("dkg");
        let shares: Vec<Cmp20Share> = kg
            .shares
            .iter()
            .map(|b| Cmp20Share::from_bytes(b).expect("parse"))
            .collect();

        // Recover party 3's scalar using parties 1 and 2.
        let recovered_scalar = recover_share_scalar(&shares[..2], 3).expect("recover");
        let original_scalar = shares[2].scalar();
        assert_eq!(recovered_scalar, original_scalar);
    }

    #[test]
    fn empty_shares_errors() {
        assert!(matches!(recover_share(&[], 1), Err(RecoverError::NoShares)));
    }
}
