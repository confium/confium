//! Ring signatures — sign as a group member without revealing which.

use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// A ring signature.
#[derive(Debug, Clone)]
pub struct RingSignature {
    /// The ring of public keys.
    pub ring: Vec<AffinePoint>,
    /// The challenge values c_0, c_1, ..., c_{n-1}.
    pub challenges: Vec<Scalar>,
    /// The response values s_0, s_1, ..., s_{n-1}.
    pub responses: Vec<Scalar>,
    /// The key image I = x_s * H_p(R).
    pub key_image: AffinePoint,
}

/// Sign a message as a member of the ring.
/// `signer_index` is the position in the ring of the actual signer.
pub fn sign(
    ring: &[AffinePoint],
    signer_index: usize,
    signer_secret: &Scalar,
    message: &[u8],
) -> Result<RingSignature, String> {
    let n = ring.len();
    if signer_index >= n {
        return Err("signer index out of bounds".into());
    }

    // Key image: I = x * H_p(R)
    let hp = hash_to_point(&ring[signer_index]);
    let key_image = (ProjectivePoint::from(hp) * signer_secret).to_affine();

    // Pick random scalar for the real signer
    let alpha = Scalar::random(&mut OsRng);
    let alpha_g = (ProjectivePoint::GENERATOR * &alpha).to_affine();
    let alpha_hp = (ProjectivePoint::from(hp) * &alpha).to_affine();

    // Compute c_{signer+1} = H(m, ring, alpha*G, alpha*Hp)
    let mut challenges = vec![Scalar::ZERO; n];
    let next_idx = (signer_index + 1) % n;
    challenges[next_idx] = challenge_hash(message, &ring, &alpha_g, &alpha_hp, &key_image);

    // Fill in challenges for all other indices
    let mut responses = vec![Scalar::ZERO; n];
    let mut i = next_idx;
    loop {
        if i == signer_index {
            break;
        }
        let s_i = Scalar::random(&mut OsRng);
        responses[i] = s_i;

        let c_i = challenges[i];
        let l_i = (ProjectivePoint::GENERATOR * &s_i
            + ProjectivePoint::from(ring[i]) * &c_i)
            .to_affine();
        let r_i = (ProjectivePoint::from(hash_to_point(&ring[i])) * &s_i
            + ProjectivePoint::from(key_image) * &c_i)
            .to_affine();

        let next = (i + 1) % n;
        challenges[next] = challenge_hash(message, &ring, &l_i, &r_i, &key_image);
        i = next;
    }

    // Close the ring: s_signer = alpha - c_signer * x
    let c_signer = challenges[signer_index];
    responses[signer_index] = alpha - c_signer * signer_secret;

    Ok(RingSignature {
        ring: ring.to_vec(),
        challenges,
        responses,
        key_image,
    })
}

/// Verify a ring signature.
pub fn verify(sig: &RingSignature, message: &[u8]) -> bool {
    let n = sig.ring.len();
    if sig.challenges.len() != n || sig.responses.len() != n {
        return false;
    }

    let mut current_challenge = sig.challenges[0];

    for i in 0..n {
        let l_i = (ProjectivePoint::GENERATOR * &sig.responses[i]
            + ProjectivePoint::from(sig.ring[i]) * &current_challenge)
            .to_affine();
        let hp_i = hash_to_point(&sig.ring[i]);
        let r_i = (ProjectivePoint::from(hp_i) * &sig.responses[i]
            + ProjectivePoint::from(sig.key_image) * &current_challenge)
            .to_affine();

        current_challenge = challenge_hash(message, &sig.ring, &l_i, &r_i, &sig.key_image);
    }

    // The loop should have come full circle
    current_challenge == sig.challenges[0]
}

fn hash_to_point(point: &AffinePoint) -> AffinePoint {
    let mut hasher = Sha256::new();
    hasher.update(b"ring-hash-to-point");
    hasher.update(point.to_encoded_point(true).as_bytes());
    let hash = hasher.finalize();
    let fb = FieldBytes::from(hash);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO);
    (ProjectivePoint::GENERATOR * &scalar).to_affine()
}

fn challenge_hash(
    message: &[u8],
    ring: &[AffinePoint],
    l: &AffinePoint,
    r: &AffinePoint,
    key_image: &AffinePoint,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"ring-challenge");
    hasher.update(message);
    for pk in ring {
        hasher.update(pk.to_encoded_point(true).as_bytes());
    }
    hasher.update(l.to_encoded_point(true).as_bytes());
    hasher.update(r.to_encoded_point(true).as_bytes());
    hasher.update(key_image.to_encoded_point(true).as_bytes());
    let fb = FieldBytes::from(hasher.finalize());
    Option::<Scalar>::from(Scalar::from_repr(fb)).unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ring(n: usize) -> Vec<(Scalar, AffinePoint)> {
        (0..n)
            .map(|_| {
                let sk = Scalar::random(&mut OsRng);
                let pk = (ProjectivePoint::GENERATOR * &sk).to_affine();
                (sk, pk)
            })
            .collect()
    }

    #[test]
    fn sign_and_verify() {
        let ring_pairs = make_ring(3);
        let ring: Vec<AffinePoint> = ring_pairs.iter().map(|(_, pk)| *pk).collect();
        let sig = sign(&ring, 0, &ring_pairs[0].0, b"message").unwrap();
        assert!(verify(&sig, b"message"));
    }

    #[test]
    fn wrong_message_rejected() {
        let ring_pairs = make_ring(3);
        let ring: Vec<AffinePoint> = ring_pairs.iter().map(|(_, pk)| *pk).collect();
        let sig = sign(&ring, 1, &ring_pairs[1].0, b"correct").unwrap();
        assert!(!verify(&sig, b"wrong"));
    }

    #[test]
    fn any_member_can_sign() {
        let ring_pairs = make_ring(5);
        let ring: Vec<AffinePoint> = ring_pairs.iter().map(|(_, pk)| *pk).collect();
        for i in 0..5 {
            let sig = sign(&ring, i, &ring_pairs[i].0, b"msg").unwrap();
            assert!(verify(&sig, b"msg"), "signer {i}");
        }
    }

    #[test]
    fn signer_index_out_of_bounds() {
        let ring_pairs = make_ring(3);
        let ring: Vec<AffinePoint> = ring_pairs.iter().map(|(_, pk)| *pk).collect();
        assert!(sign(&ring, 5, &ring_pairs[0].0, b"msg").is_err());
    }

    #[test]
    fn single_member_ring() {
        let ring_pairs = make_ring(1);
        let ring: Vec<AffinePoint> = ring_pairs.iter().map(|(_, pk)| *pk).collect();
        let sig = sign(&ring, 0, &ring_pairs[0].0, b"solo").unwrap();
        assert!(verify(&sig, b"solo"));
    }

    #[test]
    fn key_image_differs_per_signer() {
        let ring_pairs = make_ring(3);
        let ring: Vec<AffinePoint> = ring_pairs.iter().map(|(_, pk)| *pk).collect();
        let sig0 = sign(&ring, 0, &ring_pairs[0].0, b"msg").unwrap();
        let sig1 = sign(&ring, 1, &ring_pairs[1].0, b"msg").unwrap();
        assert_ne!(sig0.key_image, sig1.key_image);
    }
}
