//! Pedersen range proof — prove that a Pedersen commitment opens to a
//! value in [0, 2^bits) without revealing it.
//!
//! This is the real sigma-protocol construction the advisory process
//! specified, replacing the gated hash-based sketch: the prover
//! decomposes the value into bits, commits to each bit, and produces
//! a Cramer-Damgård-Schoenmakers OR-proof per bit that the bit
//! commitment opens to 0 or to 1. `verify` takes the value commitment
//! `C` as its statement and checks both the per-bit OR-proofs and the
//! aggregation `Σ 2^i·C_i == C`.
//!
//! Per-bit proof shape (branch k ∈ {0, 1}, statement `C_i - k·G` has
//! a pure H-opening):
//!
//! ```text
//! announcement  A_k = u_k·H
//! challenge     e_k
//! response      z_k = u_k + e_k·ρ_k
//! check         z_k·H == A_k + e_k·(C_i - k·G)
//! ```
//!
//! The real branch is proven honestly; the other is simulated with a
//! random challenge, and the two challenges sum to the per-bit
//! Fiat-Shamir challenge `H("confium-range-v1" | C | i | C_i | A_0 |
//! A_1)`, binding the whole transcript. Unaudited crate: see the lib
//! docs — this construction follows the textbook composition but has
//! had no external review.

use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::Field as _;
use p256::elliptic_curve::sec1::FromSec1Point;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// Generator pair for Pedersen commitments: `C = v·G + r·H`.
///
/// `H` is derived by try-and-increment hashing of a fixed label, so
/// nobody knows the discrete log of `H` with respect to `G`.
#[derive(Debug, Clone, Copy)]
pub struct PedersenGens {
    /// Standard base generator.
    pub g: AffinePoint,
    /// Nothing-up-my-sleeve second generator.
    pub h: AffinePoint,
}

impl PedersenGens {
    /// The standard generators: `G` plus `H = hash_to_curve(label)`.
    pub fn standard() -> Self {
        Self {
            g: ProjectivePoint::GENERATOR.to_affine(),
            h: hash_to_curve(b"confium-pedersen-h-v1"),
        }
    }
}

/// A Pedersen commitment together with its opening (prover-side).
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    /// The commitment point `C = v·G + r·H`.
    pub c: AffinePoint,
    /// The committed value.
    pub value: Scalar,
    /// The blinding factor.
    pub blind: Scalar,
}

/// Commit `value` with a fresh random blinding.
pub fn commit(gens: &PedersenGens, value: Scalar) -> PedersenCommitment {
    let blind = random_scalar();
    let c =
        (ProjectivePoint::from(gens.g) * value + ProjectivePoint::from(gens.h) * blind).to_affine();
    PedersenCommitment { c, value, blind }
}

/// A non-interactive range proof for a Pedersen commitment.
#[derive(Debug, Clone)]
pub struct PedersenRangeProof {
    /// Bit width of the proven range.
    pub bits: u32,
    /// Per-bit commitments `C_i` (bit 0 first).
    pub bit_commitments: Vec<AffinePoint>,
    /// Per-bit OR-proof announcements `[A_0, A_1]` (flattened).
    pub announcements: Vec<AffinePoint>,
    /// Per-bit challenge halves `e_0` (the other is derived).
    pub challenges: Vec<Scalar>,
    /// Per-bit responses `[z_0, z_1]` (flattened).
    pub responses: Vec<Scalar>,
}

/// Prove that `com` opens to a value in `[0, 2^bits)`.
///
/// Returns `None` when the value does not fit the bit width.
pub fn prove(
    gens: &PedersenGens,
    com: &PedersenCommitment,
    bits: u32,
) -> Option<PedersenRangeProof> {
    let bits = bits.checked_sub(1)?; // need bits >= 1
    let bits = bits + 1;
    if !fits(com.value, bits) {
        return None;
    }

    // Split the blinding so that Σ 2^i · r_i == r exactly.
    let mut r_is: Vec<Scalar> = (0..bits).map(|_| random_scalar()).collect();
    let mut weighted: Scalar = Scalar::ZERO;
    for (i, r) in r_is.iter().enumerate().take(bits as usize) {
        weighted += pow2(i as u32) * *r;
    }
    let delta = com.blind - weighted;
    // Fold the correction into the top bit's blinding (2^(bits-1) is
    // invertible mod q).
    let top = (bits - 1) as usize;
    let inv = invert(pow2(top as u32));
    r_is[top] += delta * inv;

    let g = ProjectivePoint::from(gens.g);
    let h = ProjectivePoint::from(gens.h);

    let mut bit_commitments = Vec::with_capacity(bits as usize);
    let mut announcements = Vec::with_capacity(bits as usize * 2);
    let mut challenges = Vec::with_capacity(bits as usize);
    let mut responses = Vec::with_capacity(bits as usize * 2);

    for i in 0..bits {
        let b = bit_at(com.value, i);
        let c_i =
            (g * (if b { Scalar::ONE } else { Scalar::ZERO }) + h * r_is[i as usize]).to_affine();
        bit_commitments.push(c_i);

        // Real branch j: announcement A_j = u·H, response z_j = u + e_j·ρ.
        // Simulated branch k: random e_k, z_k; A_k = z_k·H − e_k·(C_i − k·G).
        let u = random_scalar();
        let real_announce = (h * u).to_affine();

        // Simulated branch: random (e_sim, z_sim), announcement set by
        // the verification equation A = z·H − e·(C_i − k·G).
        let (e_sim, z_sim) = (random_scalar(), random_scalar());
        let sim_branch: u32 = if b { 0 } else { 1 };
        let sim_statement = if sim_branch == 0 {
            ProjectivePoint::from(c_i)
        } else {
            ProjectivePoint::from(c_i) - g
        };
        let sim_announce = (h * z_sim - sim_statement * e_sim).to_affine();

        // Branch storage order is fixed (0, 1) regardless of which is
        // real; the Fiat-Shamir challenge must be computed over the
        // STORED order so the verifier recomputes the same value.
        let (a0, a1) = if !b {
            (real_announce, sim_announce)
        } else {
            (sim_announce, real_announce)
        };
        let fs = bit_challenge(com.c, i, &c_i, &a0, &a1, bits);
        let e_real = fs - e_sim;
        let z_real = u + e_real * r_is[i as usize];

        announcements.push(a0);
        announcements.push(a1);
        if !b {
            challenges.push(e_real);
            responses.push(z_real);
            responses.push(z_sim);
        } else {
            challenges.push(e_sim);
            responses.push(z_sim);
            responses.push(z_real);
        }
    }

    Some(PedersenRangeProof {
        bits,
        bit_commitments,
        announcements,
        challenges,
        responses,
    })
}

/// Verify a range proof against the value commitment `c`.
///
/// Binds the full statement: checks the aggregation
/// `Σ 2^i·C_i == c` and every per-bit OR-proof (announcements,
/// responses, and the Fiat-Shamir challenge sum).
pub fn verify(gens: &PedersenGens, c: &AffinePoint, proof: &PedersenRangeProof) -> bool {
    let n = proof.bits as usize;
    if proof.bit_commitments.len() != n
        || proof.announcements.len() != n * 2
        || proof.challenges.len() != n
        || proof.responses.len() != n * 2
    {
        return false;
    }

    // Aggregation: Σ 2^i · C_i == c.
    let g = ProjectivePoint::from(gens.g);
    let h = ProjectivePoint::from(gens.h);
    let mut aggregate = ProjectivePoint::IDENTITY;
    for (i, c_i) in proof.bit_commitments.iter().enumerate() {
        aggregate += ProjectivePoint::from(*c_i) * pow2(i as u32);
    }
    if aggregate.to_affine() != *c {
        return false;
    }

    // Per-bit OR-proofs.
    for i in 0..n {
        let c_i = proof.bit_commitments[i];
        let a0 = proof.announcements[i * 2];
        let a1 = proof.announcements[i * 2 + 1];
        let e0 = proof.challenges[i];
        let z0 = proof.responses[i * 2];
        let z1 = proof.responses[i * 2 + 1];

        let fs = bit_challenge(*c, i as u32, &c_i, &a0, &a1, proof.bits);
        let e1 = fs - e0;

        // Branch 0: z_0·H == A_0 + e_0·C_i
        let lhs0 = h * z0;
        let rhs0 = ProjectivePoint::from(a0) + ProjectivePoint::from(c_i) * e0;
        if lhs0 != rhs0 {
            return false;
        }
        // Branch 1: z_1·H == A_1 + e_1·(C_i − G)
        let lhs1 = h * z1;
        let rhs1 = ProjectivePoint::from(a1) + (ProjectivePoint::from(c_i) - g) * e1;
        if lhs1 != rhs1 {
            return false;
        }
    }
    true
}

// ---- helpers -----------------------------------------------------------

fn bit_challenge(
    c: AffinePoint,
    i: u32,
    c_i: &AffinePoint,
    a0: &AffinePoint,
    a1: &AffinePoint,
    bits: u32,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"confium-range-v1");
    hasher.update(bits.to_be_bytes());
    hasher.update(c.to_sec1_point(true).as_bytes());
    hasher.update(i.to_be_bytes());
    hasher.update(c_i.to_sec1_point(true).as_bytes());
    hasher.update(a0.to_sec1_point(true).as_bytes());
    hasher.update(a1.to_sec1_point(true).as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    // Rejection sampling with re-hash: never a constant fallback.
    let mut bytes = bytes;
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

fn fits(v: Scalar, bits: u32) -> bool {
    // v < 2^bits ⇔ the scalar's big-endian encoding has zeros in the
    // top (256 − bits) bits.
    let repr = v.to_repr();
    repr.as_slice()[..(256 - bits) as usize / 8]
        .iter()
        .all(|&b| b == 0)
        && (((256 - bits) % 8) == 0
            || repr.as_slice()[(256 - bits) as usize / 8] < (1u8 << ((256 - bits) % 8)))
}

fn bit_at(v: Scalar, i: u32) -> bool {
    let repr = v.to_repr();
    let byte = repr.as_slice()[31 - (i / 8) as usize];
    (byte >> (i % 8)) & 1 == 1
}

fn pow2(i: u32) -> Scalar {
    // 2^i via repeated squaring — always exact, no byte fiddling.
    let two = Scalar::from(2u64);
    let mut acc = Scalar::ONE;
    let mut base = two;
    let mut e = i;
    while e > 0 {
        if e & 1 == 1 {
            acc *= base;
        }
        base = base * base;
        e >>= 1;
    }
    acc
}

fn random_scalar() -> Scalar {
    use getrandom::SysRng;
    use p256::elliptic_curve::rand_core::UnwrapErr;
    Scalar::random(&mut UnwrapErr(SysRng))
}

fn invert(s: Scalar) -> Scalar {
    Option::<Scalar>::from(s.invert()).unwrap_or(Scalar::ONE)
}

/// Try-and-increment hash-to-curve for the second generator.
fn hash_to_curve(label: &[u8]) -> AffinePoint {
    let mut counter: u32 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"confium-hash-to-curve-v1");
        hasher.update(label);
        hasher.update(counter.to_be_bytes());
        let bytes: [u8; 32] = hasher.finalize().into();
        // Candidate x-coordinate: DER-decode via SEC1 point recovery.
        let mut sec1 = [0u8; 33];
        sec1[0] = 0x02 | (bytes[31] & 1);
        sec1[1..33].copy_from_slice(&bytes);
        let enc = p256::elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_bytes(&sec1);
        if let Ok(enc) = enc {
            let p_opt = Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&enc));
            if let Some(p) = p_opt {
                // Reject the identity and the standard generator.
                if p != AffinePoint::IDENTITY && p != ProjectivePoint::GENERATOR.to_affine() {
                    return p;
                }
            }
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gens() -> PedersenGens {
        PedersenGens::standard()
    }

    fn scalar(v: u64) -> Scalar {
        Scalar::from(v)
    }

    #[test]
    fn round_trip_zero() {
        let gens = gens();
        let com = commit(&gens, scalar(0));
        let proof = prove(&gens, &com, 64).unwrap();
        assert!(verify(&gens, &com.c, &proof));
    }

    #[test]
    fn round_trip_max() {
        let gens = gens();
        let com = commit(&gens, scalar(u64::MAX));
        let proof = prove(&gens, &com, 64).unwrap();
        assert!(verify(&gens, &com.c, &proof));
    }

    #[test]
    fn round_trip_mid() {
        let gens = gens();
        let com = commit(&gens, scalar(4242));
        let proof = prove(&gens, &com, 64).unwrap();
        assert!(verify(&gens, &com.c, &proof));
    }

    #[test]
    fn round_trip_top_bit() {
        let gens = gens();
        let com = commit(&gens, scalar(1 << 63));
        let proof = prove(&gens, &com, 64).unwrap();
        assert!(verify(&gens, &com.c, &proof));
    }

    #[test]
    fn rejects_proof_for_a_different_commitment() {
        let gens = gens();
        let com = commit(&gens, scalar(42));
        let other = commit(&gens, scalar(43));
        let proof = prove(&gens, &com, 64).unwrap();
        // Valid proof, wrong statement.
        assert!(!verify(&gens, &other.c, &proof));
    }

    #[test]
    fn rejects_tampered_bit_commitment() {
        let gens = gens();
        let com = commit(&gens, scalar(300));
        let mut proof = prove(&gens, &com, 64).unwrap();
        // Flipping any bit commitment breaks the aggregation equation
        // (and the per-bit Fiat-Shamir binding).
        proof.bit_commitments[0] = (ProjectivePoint::from(proof.bit_commitments[0])
            + ProjectivePoint::from(gens.g))
        .to_affine();
        assert!(!verify(&gens, &com.c, &proof));
    }

    #[test]
    fn rejects_tampered_response() {
        let gens = gens();
        let com = commit(&gens, scalar(7));
        let mut proof = prove(&gens, &com, 64).unwrap();
        proof.responses[0] += Scalar::ONE;
        assert!(!verify(&gens, &com.c, &proof));
    }

    #[test]
    fn rejects_tampered_announcement() {
        let gens = gens();
        let com = commit(&gens, scalar(7));
        let mut proof = prove(&gens, &com, 64).unwrap();
        // The announcement is bound by Fiat-Shamir; substituting a
        // different point must fail the challenge recomputation.
        proof.announcements[1] = (ProjectivePoint::from(proof.announcements[1])
            + ProjectivePoint::from(gens.h))
        .to_affine();
        assert!(!verify(&gens, &com.c, &proof));
    }

    #[test]
    fn rejects_cross_bit_proof_splice() {
        let gens = gens();
        let com = commit(&gens, scalar(0b1011));
        let mut proof = prove(&gens, &com, 64).unwrap();
        // Swapping two bits' sub-transcripts: each bit's challenge
        // binds its own commitment index, so the splice must fail.
        proof.bit_commitments.swap(0, 1);
        proof.announcements.swap(0, 2);
        proof.announcements.swap(1, 3);
        proof.challenges.swap(0, 1);
        proof.responses.swap(0, 2);
        proof.responses.swap(1, 3);
        assert!(!verify(&gens, &com.c, &proof));
    }

    #[test]
    fn rejects_out_of_range_value_at_prove_time() {
        let gens = gens();
        // 2^64 does not fit a 64-bit range.
        let com = PedersenCommitment {
            c: (ProjectivePoint::from(gens.g) * pow2(64)
                + ProjectivePoint::from(gens.h) * scalar(5))
            .to_affine(),
            value: pow2(64),
            blind: scalar(5),
        };
        assert!(prove(&gens, &com, 64).is_none());
    }

    #[test]
    fn rejects_malformed_shape() {
        let gens = gens();
        let com = commit(&gens, scalar(1));
        let mut proof = prove(&gens, &com, 64).unwrap();
        proof.responses.pop();
        assert!(!verify(&gens, &com.c, &proof));
    }

    #[test]
    fn second_generator_is_not_the_identity_or_g() {
        let gens = gens();
        assert_ne!(gens.h, AffinePoint::IDENTITY);
        assert_ne!(gens.h, gens.g);
    }

    #[test]
    fn commitment_hides_equal_values() {
        let gens = gens();
        let a = commit(&gens, scalar(9));
        let b = commit(&gens, scalar(9));
        // Same value, different (random) blinding → different points.
        assert_ne!(a.c, b.c);
    }
}
