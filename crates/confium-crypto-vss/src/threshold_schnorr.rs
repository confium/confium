//! Threshold Schnorr (MuSig-style) — 2-round threshold signing.

use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// Round 1: each party publishes a nonce commitment.
#[derive(Debug, Clone)]
pub struct NonceCommitment {
    pub party_idx: u32,
    pub r_point: AffinePoint,
}

/// Round 2: each party publishes a partial signature.
#[derive(Debug, Clone)]
pub struct PartialSig {
    pub party_idx: u32,
    pub s_i: Scalar,
}

/// MuSig signing session.
pub struct MusigSession {
    pub public_keys: Vec<AffinePoint>,
    pub nonce_commitments: Vec<NonceCommitment>,
    pub threshold: u32,
}

impl MusigSession {
    pub fn new(public_keys: Vec<AffinePoint>, threshold: u32) -> Self {
        Self {
            public_keys,
            nonce_commitments: Vec::new(),
            threshold,
        }
    }

    /// Round 1: submit nonce commitment.
    pub fn submit_nonce(&mut self, commit: NonceCommitment) -> Result<(), String> {
        if commit.party_idx as usize >= self.public_keys.len() {
            return Err("invalid party index".into());
        }
        if self
            .nonce_commitments
            .iter()
            .any(|c| c.party_idx == commit.party_idx)
        {
            return Err("duplicate nonce".into());
        }
        self.nonce_commitments.push(commit);
        Ok(())
    }

    pub fn nonce_round_complete(&self) -> bool {
        self.nonce_commitments.len() >= self.threshold as usize
    }

    /// Compute the aggregate nonce R = sum(R_i).
    pub fn aggregate_nonce(&self) -> AffinePoint {
        let mut sum = ProjectivePoint::IDENTITY;
        for commit in &self.nonce_commitments {
            sum += ProjectivePoint::from(commit.r_point);
        }
        sum.to_affine()
    }

    /// Compute the challenge c = H(R || sum(PK) || m).
    pub fn challenge(&self, message: &[u8]) -> Scalar {
        let r = self.aggregate_nonce();
        let pk_sum = self.aggregate_public_key();
        let mut hasher = Sha256::new();
        hasher.update(b"musig-challenge");
        hasher.update(r.to_encoded_point(true).as_bytes());
        hasher.update(pk_sum.to_encoded_point(true).as_bytes());
        hasher.update(message);
        let fb = FieldBytes::from(hasher.finalize());
        Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
    }

    /// Aggregate public key: sum of all PK_i.
    pub fn aggregate_public_key(&self) -> AffinePoint {
        let mut sum = ProjectivePoint::IDENTITY;
        for pk in &self.public_keys {
            sum += ProjectivePoint::from(*pk);
        }
        sum.to_affine()
    }
}

/// Party i computes their partial signature: s_i = k_i + c * x_i.
pub fn compute_partial_sig(k_i: &Scalar, x_i: &Scalar, challenge: &Scalar) -> PartialSig {
    PartialSig {
        party_idx: 0, // set by caller
        s_i: *k_i + *challenge * *x_i,
    }
}

/// Combine partial signatures into a full Schnorr signature.
pub fn combine(partials: &[PartialSig]) -> Scalar {
    partials
        .iter()
        .map(|p| p.s_i)
        .fold(Scalar::ZERO, |acc, s| acc + s)
}

/// Verify a MuSig signature: s * G == R + c * agg_pk.
pub fn verify(s: &Scalar, r: &AffinePoint, agg_pk: &AffinePoint, challenge: &Scalar) -> bool {
    let lhs = ProjectivePoint::GENERATOR * s;
    let rhs = ProjectivePoint::from(*r) + ProjectivePoint::from(*agg_pk) * challenge;
    lhs == rhs
}

/// Generate a random nonce for a party.
pub fn generate_nonce(party_idx: u32) -> (Scalar, NonceCommitment) {
    let k = Scalar::random(&mut OsRng);
    let r_point = (ProjectivePoint::GENERATOR * k).to_affine();
    (k, NonceCommitment { party_idx, r_point })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypairs(n: usize) -> Vec<(Scalar, AffinePoint)> {
        (0..n)
            .map(|_| {
                let sk = Scalar::random(&mut OsRng);
                let pk = (ProjectivePoint::GENERATOR * &sk).to_affine();
                (sk, pk)
            })
            .collect()
    }

    #[test]
    fn full_musig_round() {
        let pairs = make_keypairs(3);
        let pks: Vec<AffinePoint> = pairs.iter().map(|(_, pk)| *pk).collect();
        let mut session = MusigSession::new(pks.clone(), 3);

        // Round 1: nonces
        let mut nonces = Vec::new();
        for i in 0..3 {
            let (k, commit) = generate_nonce(i as u32);
            session.submit_nonce(commit).unwrap();
            nonces.push(k);
        }
        assert!(session.nonce_round_complete());

        // Round 2: partial sigs
        let c = session.challenge(b"message");
        let mut partials = Vec::new();
        for i in 0..3 {
            let mut ps = compute_partial_sig(&nonces[i], &pairs[i].0, &c);
            ps.party_idx = i as u32;
            partials.push(ps);
        }

        // Combine
        let s = combine(&partials);
        let r = session.aggregate_nonce();
        let agg_pk = session.aggregate_public_key();

        // Verify
        assert!(verify(&s, &r, &agg_pk, &c));
    }

    #[test]
    fn nonce_round_incomplete() {
        let pairs = make_keypairs(3);
        let pks: Vec<AffinePoint> = pairs.iter().map(|(_, pk)| *pk).collect();
        let mut session = MusigSession::new(pks, 2);
        let (_, commit) = generate_nonce(0);
        session.submit_nonce(commit).unwrap();
        assert!(!session.nonce_round_complete());
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let pairs = make_keypairs(2);
        let pks: Vec<AffinePoint> = pairs.iter().map(|(_, pk)| *pk).collect();
        let mut session = MusigSession::new(pks, 2);
        let (_, c1) = generate_nonce(0);
        let (_, c2) = generate_nonce(0);
        session.submit_nonce(c1).unwrap();
        assert!(session.submit_nonce(c2).is_err());
    }

    #[test]
    fn aggregate_public_key_correct() {
        let pairs = make_keypairs(3);
        let pks: Vec<AffinePoint> = pairs.iter().map(|(_, pk)| *pk).collect();
        let session = MusigSession::new(pks.clone(), 3);
        let agg = session.aggregate_public_key();
        let mut expected = ProjectivePoint::IDENTITY;
        for (_, pk) in &pairs {
            expected += ProjectivePoint::from(*pk);
        }
        assert_eq!(agg, expected.to_affine());
    }

    #[test]
    fn two_party_musig() {
        let pairs = make_keypairs(2);
        let pks: Vec<AffinePoint> = pairs.iter().map(|(_, pk)| *pk).collect();
        let mut session = MusigSession::new(pks, 2);

        let mut nonces = Vec::new();
        for i in 0..2 {
            let (k, commit) = generate_nonce(i as u32);
            session.submit_nonce(commit).unwrap();
            nonces.push(k);
        }

        let c = session.challenge(b"2-party");
        let partials: Vec<PartialSig> = (0..2)
            .map(|i| {
                let mut ps = compute_partial_sig(&nonces[i], &pairs[i].0, &c);
                ps.party_idx = i as u32;
                ps
            })
            .collect();

        let s = combine(&partials);
        let r = session.aggregate_nonce();
        let agg_pk = session.aggregate_public_key();
        assert!(verify(&s, &r, &agg_pk, &c));
    }

    #[test]
    fn wrong_s_rejected() {
        let pairs = make_keypairs(2);
        let pks: Vec<AffinePoint> = pairs.iter().map(|(_, pk)| *pk).collect();
        let session = MusigSession::new(pks.clone(), 2);
        let r = (ProjectivePoint::GENERATOR * &Scalar::random(&mut OsRng)).to_affine();
        let agg_pk = session.aggregate_public_key();
        let c = session.challenge(b"test");
        let wrong_s = Scalar::random(&mut OsRng);
        assert!(!verify(&wrong_s, &r, &agg_pk, &c));
    }
}
