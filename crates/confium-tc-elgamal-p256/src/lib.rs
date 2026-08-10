//! Threshold ElGamal over P-256.
//!
//! Real implementation using P-256 group operations. Threshold variant:
//! the secret key `x` is Shamir-shared among N parties; any T can
//! decrypt collaboratively. The decryption produces the original
//! shared secret point.
//!
//! Used for medium-term sealed data (5-10 year appeals window in OIML CNML).
//!
//! See `TODO.roadmap/31-threshold-encryption.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod keys;
pub mod shamir;

use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::rand_core;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::subtle::CtOption;
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};

pub use keys::generate_keypair;
pub use shamir::{Share, recover_secret, split_secret};

/// Algorithm identifier.
pub const ALGORITHM: &str = "ElGamal-P256-threshold";

/// Public key wrapping an affine P-256 point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// SEC1-encoded public key bytes (uncompressed, 65 bytes).
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Construct from an affine point.
    pub fn from_affine(point: AffinePoint) -> Self {
        Self {
            bytes: point.to_encoded_point(false).as_bytes().to_vec(),
        }
    }
}

/// Share of the secret key held by one party.
/// The secret `bytes` field is zeroized on drop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// Party index.
    pub party_index: u32,
    /// Scalar share bytes (32 bytes).
    pub bytes: Vec<u8>,
}

impl Drop for DecryptionShare {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

/// Ciphertext: pair of EC points (c1, c2) per ElGamal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// SEC1-encoded c1 (ephemeral public key).
    pub c1: Vec<u8>,
    /// SEC1-encoded c2 (shared_secret_point + plaintext_point).
    pub c2: Vec<u8>,
}

/// A partial decryption from one party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// Contributing party index.
    pub party_index: u32,
    /// SEC1-encoded point.
    pub bytes: Vec<u8>,
}

/// Errors during threshold ElGamal operations.
#[derive(Debug, thiserror::Error)]
pub enum ElGamalError {
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Count received.
        have: usize,
        /// Required threshold.
        need: u32,
    },
    /// SEC1 decoding failure.
    #[error("SEC1 decode failed: {0}")]
    Sec1Decode(String),
    /// Duplicate party indices.
    #[error("duplicate party index: {0}")]
    DuplicateParty(u32),
    /// Invalid scalar bytes.
    #[error("invalid scalar: {0}")]
    InvalidScalar(String),
}

fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint, ElGamalError> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    let ep = p256::EncodedPoint::from_bytes(bytes)
        .map_err(|e| ElGamalError::Sec1Decode(format!("encoded point: {e}")))?;
    let ct_opt: CtOption<AffinePoint> = AffinePoint::from_encoded_point(&ep);
    let affine = Option::<AffinePoint>::from(ct_opt)
        .ok_or_else(|| ElGamalError::Sec1Decode("point at infinity".into()))?;
    Ok(ProjectivePoint::from(affine))
}

fn encode_point(point: &ProjectivePoint) -> Vec<u8> {
    point
        .to_affine()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn decode_scalar(bytes: &[u8]) -> Result<Scalar, ElGamalError> {
    if bytes.len() != 32 {
        return Err(ElGamalError::InvalidScalar(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let fb = FieldBytes::from(arr);
    let ct: CtOption<Scalar> = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).ok_or_else(|| ElGamalError::InvalidScalar("out of range".into()))
}

/// Encapsulate a fresh shared secret to `recipient_public_key`.
///
/// Standard ElGamal:
/// - Generate ephemeral scalar `r`
/// - c1 = r * G
/// - c2 = r * recipient_pubkey
/// - shared_secret = X-coordinate of c2 (32 bytes)
///
/// The receiver threshold-decrypts to recover the same c2 point, then
/// takes its X-coordinate as the shared secret.
pub fn encapsulate(
    recipient_public_key: &PublicKey,
) -> Result<(Ciphertext, Vec<u8>), ElGamalError> {
    use p256::elliptic_curve::rand_core::RngCore;

    let recipient_pt = decode_point(&recipient_public_key.bytes)?;

    // Random ephemeral scalar
    let r = loop {
        let mut buf = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut buf);
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(buf))) {
            if s != Scalar::ZERO {
                break s;
            }
        }
    };

    let c1 = ProjectivePoint::GENERATOR * r;
    let c2 = recipient_pt * r;

    let c1_bytes = encode_point(&c1);
    let c2_bytes = encode_point(&c2);
    let shared_secret = x_coordinate(&c2);

    Ok((
        Ciphertext {
            c1: c1_bytes,
            c2: c2_bytes,
        },
        shared_secret,
    ))
}

/// Compute a partial decryption: `share * c1`.
pub fn partial_decrypt(
    share: &DecryptionShare,
    ciphertext: &Ciphertext,
) -> Result<PartialDecryption, ElGamalError> {
    let s = decode_scalar(&share.bytes)?;
    let c1 = decode_point(&ciphertext.c1)?;
    let partial = c1 * s;
    Ok(PartialDecryption {
        party_index: share.party_index,
        bytes: encode_point(&partial),
    })
}

/// Aggregate T partial decryptions into the shared secret point.
///
/// For KEM-style encapsulate (shared_secret = X(r * recipient_pubkey)):
/// the shared secret point is `combined = sum_i λ_i * partial_i = x * c1`.
/// Returns the X-coordinate of `combined` (32 bytes).
pub fn aggregate_partials(
    partials: &[PartialDecryption],
    threshold: u32,
    _ciphertext: &Ciphertext,
) -> Result<Vec<u8>, ElGamalError> {
    if (partials.len() as u32) < threshold {
        return Err(ElGamalError::ThresholdNotMet {
            have: partials.len(),
            need: threshold,
        });
    }

    let mut seen = std::collections::HashSet::new();
    for p in partials {
        if !seen.insert(p.party_index) {
            return Err(ElGamalError::DuplicateParty(p.party_index));
        }
    }

    // combined = sum_i [ λ_i * partial_i ] = x * c1 = r * recipient_pubkey (for KEM)
    let mut combined = ProjectivePoint::IDENTITY;
    for p_i in partials {
        let x_i = party_to_scalar(p_i.party_index);
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for p_j in partials {
            if p_j.party_index == p_i.party_index {
                continue;
            }
            let x_j = party_to_scalar(p_j.party_index);
            numerator *= negate(&x_j);
            denominator *= x_i.sub(&x_j);
        }
        let denom_inv = invert(&denominator);
        let lagrange = numerator * denom_inv;

        let partial_point = decode_point(&p_i.bytes)?;
        let weighted = partial_point * lagrange;
        combined = combined.add(&weighted);
    }

    Ok(x_coordinate(&combined))
}

fn x_coordinate(point: &ProjectivePoint) -> Vec<u8> {
    let affine = point.to_affine();
    let ep = affine.to_encoded_point(false);
    let bytes = ep.as_bytes();
    if bytes.len() == 65 {
        bytes[1..33].to_vec()
    } else {
        bytes.to_vec()
    }
}

fn negate(s: &Scalar) -> Scalar {
    Scalar::ZERO.sub(s)
}

fn invert(s: &Scalar) -> Scalar {
    let ct: CtOption<Scalar> = s.invert();
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

fn party_to_scalar(v: u32) -> Scalar {
    let mut arr = [0u8; 32];
    arr[28..32].copy_from_slice(&v.to_be_bytes());
    let fb = FieldBytes::from(arr);
    let ct: CtOption<Scalar> = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_then_aggregate_round_trip() {
        // 1. Generate keypair, split into 3 shares (T=2).
        let keypair = generate_keypair();
        let pk = PublicKey::from_affine(keypair.public_key);
        let shares = split_secret(&keypair.secret_scalar, 2, 3);

        // 2. Encapsulate to pk.
        let (ciphertext, shared_secret) = encapsulate(&pk).unwrap();
        assert_eq!(shared_secret.len(), 32);

        // 3. Each of T shares computes partial decryption.
        let decryption_shares: Vec<DecryptionShare> = shares
            .iter()
            .map(|s| DecryptionShare {
                party_index: s.x,
                bytes: {
                    let fb: FieldBytes = s.y.to_bytes();
                    let arr: [u8; 32] = fb.into();
                    arr.to_vec()
                },
            })
            .collect();
        let partials: Vec<PartialDecryption> = decryption_shares
            .iter()
            .take(2)
            .map(|ds| partial_decrypt(ds, &ciphertext).unwrap())
            .collect();

        // 4. Aggregate.
        let recovered = aggregate_partials(&partials, 2, &ciphertext).unwrap();
        assert_eq!(recovered.len(), 32);
        // X-coordinate of c2 matches shared secret.
        assert_eq!(recovered, shared_secret);
    }

    #[test]
    fn aggregate_below_threshold_fails() {
        let keypair = generate_keypair();
        let pk = PublicKey::from_affine(keypair.public_key);
        let shares = split_secret(&keypair.secret_scalar, 3, 5);
        let (ciphertext, _) = encapsulate(&pk).unwrap();
        let decryption_shares: Vec<DecryptionShare> = shares
            .iter()
            .map(|s| DecryptionShare {
                party_index: s.x,
                bytes: {
                    let fb: FieldBytes = s.y.to_bytes();
                    let arr: [u8; 32] = fb.into();
                    arr.to_vec()
                },
            })
            .collect();
        let partials: Vec<PartialDecryption> = decryption_shares
            .iter()
            .take(2)
            .map(|ds| partial_decrypt(ds, &ciphertext).unwrap())
            .collect();
        let result = aggregate_partials(&partials, 3, &ciphertext);
        assert!(matches!(result, Err(ElGamalError::ThresholdNotMet { .. })));
    }

    #[test]
    fn different_share_subsets_recover_same_secret() {
        let keypair = generate_keypair();
        let pk = PublicKey::from_affine(keypair.public_key);
        let shares = split_secret(&keypair.secret_scalar, 3, 5);
        let (ciphertext, shared_secret) = encapsulate(&pk).unwrap();

        let decryption_shares: Vec<DecryptionShare> = shares
            .iter()
            .map(|s| DecryptionShare {
                party_index: s.x,
                bytes: {
                    let fb: FieldBytes = s.y.to_bytes();
                    let arr: [u8; 32] = fb.into();
                    arr.to_vec()
                },
            })
            .collect();

        // Subset A: shares 0, 1, 2
        let partials_a: Vec<PartialDecryption> = decryption_shares[0..3]
            .iter()
            .map(|ds| partial_decrypt(ds, &ciphertext).unwrap())
            .collect();
        let recovered_a = aggregate_partials(&partials_a, 3, &ciphertext).unwrap();

        // Subset B: shares 2, 3, 4
        let partials_b: Vec<PartialDecryption> = decryption_shares[2..5]
            .iter()
            .map(|ds| partial_decrypt(ds, &ciphertext).unwrap())
            .collect();
        let recovered_b = aggregate_partials(&partials_b, 3, &ciphertext).unwrap();

        assert_eq!(recovered_a, shared_secret);
        assert_eq!(recovered_b, shared_secret);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // For any threshold T in [2, 5] and party count N in [T, 8],
    // the threshold ElGamal round-trip must produce the same shared secret.
    proptest! {
        #[test]
        fn elgamal_roundtrip_any_threshold(t in 2u32..=5, n in 5u32..=8) {
            let kp = generate_keypair();
            let pub_key = PublicKey::from_affine(kp.public_key);
            let shares = split_secret(&kp.secret_scalar, t, n);
            let decryption_shares: Vec<DecryptionShare> = shares
                .iter()
                .map(|s| DecryptionShare {
                    party_index: s.x,
                    bytes: {
                        let fb: FieldBytes = s.y.to_bytes();
                        let arr: [u8; 32] = fb.into();
                        arr.to_vec()
                    },
                })
                .collect();

            let (ciphertext, shared_secret) = encapsulate(&pub_key)?;

            let partials: Vec<PartialDecryption> = decryption_shares[..t as usize]
                .iter()
                .map(|ds| partial_decrypt(ds, &ciphertext).unwrap())
                .collect();
            let recovered = aggregate_partials(&partials, t, &ciphertext)?;

            prop_assert_eq!(recovered, shared_secret);
        }
    }

    // Threshold invariant: T shares recover the secret, T-1 do NOT.
    proptest! {
        #[test]
        fn elgamal_below_threshold_fails(t in 2u32..=4, n in 5u32..=8) {
            let kp = generate_keypair();
            let pub_key = PublicKey::from_affine(kp.public_key);
            let shares = split_secret(&kp.secret_scalar, t, n);
            let decryption_shares: Vec<DecryptionShare> = shares
                .iter()
                .map(|s| DecryptionShare {
                    party_index: s.x,
                    bytes: {
                        let fb: FieldBytes = s.y.to_bytes();
                        let arr: [u8; 32] = fb.into();
                        arr.to_vec()
                    },
                })
                .collect();

            let (ciphertext, _) = encapsulate(&pub_key)?;

            let partials: Vec<PartialDecryption> = decryption_shares[..(t - 1) as usize]
                .iter()
                .map(|ds| partial_decrypt(ds, &ciphertext).unwrap())
                .collect();
            let result = aggregate_partials(&partials, t, &ciphertext);
            prop_assert!(result.is_err(), "below-threshold should fail");
        }
    }
}
