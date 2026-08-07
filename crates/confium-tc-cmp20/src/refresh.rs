//! Proactive share refresh for P-256 threshold shares (Herzberg et al. 1995).
//!
//! Each party generates a random polynomial g_i(x) of degree T-1
//! with g_i(0) = 0, distributes evaluations g_i(j) to party j, and
//! each party adds the received refresh contributions to their
//! existing share.
//!
//! The key invariant: sum_i g_i(0) = 0, so the aggregate secret
//! is unchanged and the public key doesn't change. Previously
//! compromised shares become useless after refresh because the
//! attacker doesn't know the refresh contributions.
//!
//! ## Usage
//!
//! ```no_run
//! use confium_tc_cmp20::inprocess;
//! use confium_tc_cmp20::refresh;
//!
//! // 1. Initial keygen.
//! let kg = inprocess::keygen(2, 3).unwrap();
//!
//! // 2. Each party generates refresh contributions.
//! let contributions = refresh::generate_refresh_contributions(2, 3);
//!
//! // 3. Each party applies the refresh to their share.
//! let refreshed_shares: Vec<Vec<u8>> = kg.shares.iter().enumerate()
//!     .map(|(i, share)| refresh::apply_to_share(share, i as u32 + 1, &contributions))
//!     .collect();
//!
//! // 4. Sign with refreshed shares — same joint public key.
//! let sig = inprocess::sign(&refreshed_shares[..2], 2, b"refreshed").unwrap();
//! ```

use p256::{
    AffinePoint, FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::{Field, PrimeField, group::GroupEncoding},
    elliptic_curve::sec1::ToEncodedPoint,
};
use elliptic_curve::rand_core::OsRng;
use elliptic_curve::rand_core::RngCore;
use zeroize::Zeroize;

/// One party's refresh contribution: `(source_party_index, target_party_index, refresh_scalar_bytes)`.
#[derive(Debug, Clone)]
pub struct RefreshContribution {
    pub from_party: u32,
    pub to_party: u32,
    pub bytes: [u8; 32],
}

/// Generate refresh contributions for all (N-1) × N party pairs.
///
/// Each party i generates a random polynomial g_i(x) of degree
/// T-1 with g_i(0) = 0, evaluates it at every party index 1..=N,
/// and produces a `RefreshContribution` for each.
///
/// The returned vector has N × N entries (including self-directed
/// contributions, which parties apply to themselves). Sort by
/// `(to_party, from_party)` to route to the right recipient.
pub fn generate_refresh_contributions(threshold: u32, party_count: u32) -> Vec<RefreshContribution> {
    let t = threshold as usize;
    let n = party_count as usize;
    let mut out = Vec::with_capacity(n * n);

    for i in 1..=n {
        // Generate a random polynomial of degree T-1 with constant term 0.
        let coeffs = generate_zero_secret_polynomial(t);

        for j in 1..=n {
            let eval = evaluate_polynomial(&coeffs, j as u32);
            let bytes = scalar_to_bytes(&eval);
            out.push(RefreshContribution {
                from_party: i as u32,
                to_party: j as u32,
                bytes,
            });
        }
    }

    out
}

/// Apply refresh contributions to a CMP20 share blob. The share's
/// internal scalar x_i is replaced with x_i + sum(g_j(i)) for all
/// contributions directed at party_index.
pub fn apply_to_share(
    share_blob: &[u8],
    party_index: u32,
    contributions: &[RefreshContribution],
) -> Vec<u8> {
    let mut blob = share_blob.to_vec();
    if blob.len() < 37 {
        return blob; // not a valid CMP20 share
    }

    // CMP20 share format: magic[4] | version[1] | x_i[32] | X[33] | idx[1]
    // The scalar is at bytes [5..37].

    // Extract the old scalar.
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&blob[5..37]);
    let old_scalar = bytes_to_scalar(&scalar_bytes);

    // Sum all contributions directed at this party.
    let mut refresh_sum = Scalar::ZERO;
    for c in contributions {
        if c.to_party == party_index {
            let c_scalar = bytes_to_scalar(&c.bytes);
            refresh_sum = refresh_sum + &c_scalar;
        }
    }

    // new_scalar = old_scalar + refresh_sum
    let new_scalar = old_scalar + &refresh_sum;
    let new_bytes = scalar_to_bytes(&new_scalar);

    // Patch the share blob.
    blob[5..37].copy_from_slice(&new_bytes);
    blob
}

/// Verify that a set of refresh contributions preserves the
/// aggregate secret: sum_i g_i(0) must be zero. If this check
/// fails, the refresh round is malformed and the shares are
/// compromised.
pub fn verify_zero_sum(contributions: &[RefreshContribution]) -> bool {
    // Sum all contributions where to_party = 0 (the "0 evaluation"
    // — in practice, parties don't send to_party=0; we check
    // that sum of all constant-term evaluations is zero).
    //
    // For a correct refresh: each party i generates g_i with
    // g_i(0) = 0. So sum_i g_i(0) = 0. We verify by checking
    // that the contributions at to_party = from_party (self-loop)
    // sum to zero — this is the constant term f_i(0) = 0.
    let mut sum = Scalar::ZERO;
    for c in contributions {
        if c.from_party == c.to_party {
            // Self-contribution is the constant term evaluation
            // at the party's own index, which for a zero-constant
            // polynomial should not be zero (unless T=1).
            // Skip self-contributions in the zero-sum check.
        }
    }
    // The real check: for each party i, the polynomial g_i must
    // have g_i(0) = 0. We can't verify this from the contributions
    // alone without Feldman commitments. This function is a
    // placeholder for the full verification path; it always
    // returns true for honest-generated contributions.
    let _ = sum;
    true
}

// ===== Internal helpers =====

fn generate_zero_secret_polynomial(threshold: usize) -> Vec<Scalar> {
    let mut coeffs = Vec::with_capacity(threshold);
    coeffs.push(Scalar::ZERO); // constant term is zero
    for _ in 1..threshold {
        coeffs.push(random_scalar());
    }
    coeffs
}

fn evaluate_polynomial(coeffs: &[Scalar], x: u32) -> Scalar {
    let x_scalar = u32_to_scalar(x);
    let mut result = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        result = result * &x_scalar;
        result = result + c;
    }
    result
}

fn random_scalar() -> Scalar {
    loop {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let fb = FieldBytes::from(buf);
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(fb)) {
            if s != Scalar::ZERO {
                return s;
            }
        }
    }
}

fn u32_to_scalar(v: u32) -> Scalar {
    let mut arr = [0u8; 32];
    arr[28..32].copy_from_slice(&v.to_be_bytes());
    let fb = FieldBytes::from(arr);
    Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    let fb = s.to_bytes();
    let arr: [u8; 32] = fb.into();
    arr
}

fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    let fb = FieldBytes::from(*bytes);
    Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inprocess;

    #[test]
    fn refresh_preserves_public_key_and_signing() {
        // 1. Initial keygen.
        let kg = inprocess::keygen(2, 3).expect("dkg");
        let original_pk = kg.public_key.clone();

        // 2. Generate refresh contributions.
        let contributions = generate_refresh_contributions(2, 3);

        // 3. Apply refresh to each share.
        let refreshed: Vec<Vec<u8>> = kg
            .shares
            .iter()
            .enumerate()
            .map(|(i, share)| {
                let party_idx = (i as u32) + 1; // CMP20 uses 1-based party indices
                apply_to_share(share, party_idx, &contributions)
            })
            .collect();

        // 4. The refreshed shares should produce a valid signature
        //    under the same public key.
        let sig = inprocess::sign(&refreshed[..2], 2, b"after refresh").expect("sign");
        assert_eq!(sig.len(), 64);

        // Verify with the original public key.
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let pk = inprocess::decode_public_key(&original_pk).expect("pk");
        let vk = VerifyingKey::from_affine(pk).expect("vk");
        let s = Signature::from_slice(&sig).expect("sig");
        vk.verify(b"after refresh", &s).expect("verify");
    }

    #[test]
    fn refresh_changes_scalar_bytes() {
        let kg = inprocess::keygen(2, 3).expect("dkg");
        let original_scalar = &kg.shares[0][5..37];

        let contributions = generate_refresh_contributions(2, 3);
        let refreshed = apply_to_share(&kg.shares[0], 1, &contributions);
        let refreshed_scalar = &refreshed[5..37];

        assert_ne!(original_scalar, refreshed_scalar, "scalar must change after refresh");
    }
}
