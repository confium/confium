//! Polynomial helpers for verifiable secret sharing.
//!
//! FROST's DKG and signing both rest on Shamir-style secret sharing over
//! the scalar field: a secret `a_0` is committed as the constant term of
//! a degree-`T-1` polynomial `f(X) = a_0 + a_1·X + … + a_{T-1}·X^{T-1}`,
//! and party `i`'s share is `f(i)`. [`lagrange_coefficient`] rebuilds the
//! original secret (or any linear function of it) from any `T` shares via
//! interpolation, without ever recombining the shares themselves.

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::group;

/// Compute the Lagrange coefficient `λ_i` for party `i` relative to the
/// participating set `S` (party indices, all distinct). The coefficient is
///
/// ```text
///   λ_i = ∏_{j ∈ S, j ≠ i}  j / (j - i)
/// ```
///
/// evaluated in the scalar field mod ℓ. Used both during DKG (to weight
/// per-party VSS contributions) and during signing (to weight share
/// responses).
///
/// Panics if `i` is not in `participants`. Callers must ensure the roster
/// is well-formed before calling.
pub fn lagrange_coefficient(i: u32, participants: &[u32]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    let i_scalar = Scalar::from(i);
    for &j in participants {
        if j == i {
            continue;
        }
        let j_scalar = Scalar::from(j);
        num *= j_scalar;
        den *= j_scalar - i_scalar;
    }
    num * den.invert()
}

/// A degree-`(t-1)` polynomial over the scalar field used for VSS.
/// Coefficients are little-endian: `f(X) = sum coeff[k] * X^k`.
pub struct Polynomial {
    coeff: Vec<Scalar>,
}

impl Polynomial {
    /// Build a polynomial from its coefficient vector. `coeff[0]` is the
    /// constant term (the committed secret for a VSS polynomial).
    pub fn from_coefficients(coeff: Vec<Scalar>) -> Self {
        debug_assert!(!coeff.is_empty(), "polynomial must have at least one term");
        Polynomial { coeff }
    }

    /// Number of coefficients — equal to the threshold `T` for a degree
    /// `T-1` polynomial.
    pub fn degree_plus_one(&self) -> usize {
        self.coeff.len()
    }

    /// The constant term `f(0)` — the committed secret.
    pub fn constant(&self) -> Scalar {
        self.coeff[0]
    }

    /// Borrow the coefficient vector.
    pub fn coefficients(&self) -> &[Scalar] {
        &self.coeff
    }

    /// Evaluate `f(x)` at a party index using Horner's rule.
    pub fn evaluate(&self, x: u32) -> Scalar {
        let x_scalar = Scalar::from(x);
        let mut acc = *self.coeff.last().expect("non-empty polynomial");
        for c in self.coeff[..self.coeff.len() - 1].iter().rev() {
            acc = acc * x_scalar + c;
        }
        acc
    }
}

/// A Feldman-style commitment list to a VSS polynomial: `C_k = a_k · B`
/// for each coefficient `a_k`. Reveal nothing about the secret beyond what
/// the public key already does (since `C_0 = A`, the public key), but let
/// recipients verify that a share `f(i)` is consistent with the
/// committed polynomial via `f(i)·B == Σ_k i^k · C_k`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentList {
    /// `C_k = a_k · B`, encoded as 32-byte compressed points.
    commits: Vec<[u8; group::ELEMENT_BYTES]>,
}

impl CommitmentList {
    /// Build from already-encoded commitment bytes.
    pub fn from_bytes(commits: Vec<[u8; group::ELEMENT_BYTES]>) -> Self {
        CommitmentList { commits }
    }

    /// Build by committing each coefficient of `poly` to the base point.
    pub fn commit(poly: &Polynomial) -> Self {
        let commits = poly
            .coefficients()
            .iter()
            .map(|a| group::point_to_bytes(&group::mul_base(a)))
            .collect();
        CommitmentList { commits }
    }

    /// The aggregate public key `A = C_0 = a_0 · B` as compressed bytes.
    pub fn public_key_bytes(&self) -> [u8; group::ELEMENT_BYTES] {
        self.commits[0]
    }

    /// The full commitment list as compressed-point bytes.
    pub fn as_bytes(&self) -> &[[u8; group::ELEMENT_BYTES]] {
        &self.commits
    }

    /// Verify a share `s_i` claimed to be `f(i)` for the polynomial this
    /// list commits to. Returns `true` iff `s_i · B == Σ_k i^k · C_k`.
    pub fn verify_share(&self, participant: u32, share: &Scalar) -> bool {
        let lhs = group::mul_base(share);
        // Compute Σ_k i^k · C_k via Horner on the decompressed commitments.
        // Walk coefficients high → low so we can fold in powers of i.
        let i_scalar = Scalar::from(participant);
        let mut acc = curve25519_dalek::edwards::EdwardsPoint::identity();
        for c_bytes in self.commits.iter().rev() {
            let c = match group::point_from_bytes(c_bytes) {
                Some(p) => p,
                None => return false,
            };
            acc = acc * i_scalar + c;
        }
        acc == lhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn lagrange_of_single_party_is_one() {
        let lambda = lagrange_coefficient(1, &[1]);
        assert_eq!(lambda, Scalar::ONE);
    }

    #[test]
    fn lagrange_coefficients_recover_secret() {
        // f(X) = a0 + a1·X with a0 = 7, a1 = 3. Shares: f(1) = 10, f(2) = 13.
        let a0 = Scalar::from(7u64);
        let a1 = Scalar::from(3u64);
        let poly = Polynomial::from_coefficients(vec![a0, a1]);
        let s1 = poly.evaluate(1);
        let s2 = poly.evaluate(2);
        assert_eq!(s1, Scalar::from(10u64));
        assert_eq!(s2, Scalar::from(13u64));
        // Recover a0 from {1, 2} via Lagrange.
        let l1 = lagrange_coefficient(1, &[1, 2]);
        let l2 = lagrange_coefficient(2, &[1, 2]);
        let recovered = s1 * l1 + s2 * l2;
        assert_eq!(recovered, a0);
    }

    #[test]
    fn polynomial_evaluate_matches_definition() {
        let coeff = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let poly = Polynomial::from_coefficients(coeff);
        // f(5) = 1 + 2·5 + 3·25 = 1 + 10 + 75 = 86
        let got = poly.evaluate(5);
        let want = Scalar::from(86u64);
        assert_eq!(got, want);
    }

    #[test]
    fn commitment_list_verifies_valid_share() {
        let poly = Polynomial::from_coefficients(vec![
            Scalar::from(11u64),
            Scalar::from(7u64),
            Scalar::from(3u64),
        ]);
        let cl = CommitmentList::commit(&poly);
        // party 2's share
        let s2 = poly.evaluate(2);
        assert!(cl.verify_share(2, &s2));
        // wrong share fails
        let bad = s2 + Scalar::ONE;
        assert!(!cl.verify_share(2, &bad));
    }

    #[test]
    fn commitment_list_public_key_matches_constant_term() {
        let poly = Polynomial::from_coefficients(vec![Scalar::from(42u64), Scalar::from(9u64)]);
        let cl = CommitmentList::commit(&poly);
        let want = group::point_to_bytes(&group::mul_base(&Scalar::from(42u64)));
        assert_eq!(cl.public_key_bytes(), want);
    }
}
