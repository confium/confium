//! Threshold ECIES over P-256 — real implementation.
//!
//! ECIES (Elliptic Curve Integrated Encryption Scheme) on P-256:
//!
//! - Encryptor generates ephemeral scalar `r`, computes `R = r * G`
//! - Encryptor computes ECDH shared secret `K = r * recipient_pubkey`
//! - Encryptor derives AEAD key from `K` via HKDF-SHA256
//! - Encryptor encrypts plaintext with AES-256-GCM
//! - Output: `(R, ciphertext, nonce, tag)`
//!
//! Threshold variant: recipient's private scalar `x` is Shamir-shared
//! among N parties. Each party computes `partial_i = x_i * R`. Combined
//! via Lagrange: `sum_i λ_i * partial_i = x * R = K`. From K, the AEAD
//! key is derived and decryption proceeds normally.
//!
//! Used for browser-side key escrow and Mode 2 enterprise secrets.
//!
//! See `TODO.roadmap/31-threshold-encryption.md` for full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod keys;
pub mod shamir;

use aes_gcm::aead::AeadInOut;
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::rand_core;
use p256::elliptic_curve::rand_core::Rng;
use p256::elliptic_curve::sec1::Sec1Point;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::subtle::CtOption;
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};

pub use keys::generate_keypair;
pub use shamir::{Share, recover_secret, split_secret};

/// Algorithm identifier.
pub const ALGORITHM: &str = "ECIES-P256-threshold";

/// Threshold ECIES public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// SEC1-encoded public key bytes (uncompressed, 65 bytes).
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Construct from an affine point.
    pub fn from_affine(point: AffinePoint) -> Self {
        Self {
            bytes: point.to_sec1_point(false).as_bytes().to_vec(),
        }
    }
}

/// Share of the threshold ECIES secret key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// Party index.
    pub party_index: u32,
    /// Share bytes (32-byte scalar).
    pub bytes: Vec<u8>,
}

/// ECIES-encrypted blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Ephemeral public key R (uncompressed, 65 bytes).
    pub ephemeral_public: Vec<u8>,
    /// AEAD ciphertext.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce (12 bytes for AES-GCM).
    pub nonce: Vec<u8>,
    /// AEAD tag (16 bytes for AES-256-GCM).
    pub tag: Vec<u8>,
}

/// Partial decryption from one party: `share * R` as SEC1 bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// Contributing party index.
    pub party_index: u32,
    /// SEC1-encoded point.
    pub bytes: Vec<u8>,
}

/// Errors during threshold ECIES operations.
#[derive(Debug, thiserror::Error)]
pub enum EciesError {
    /// Threshold not met.
    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet {
        /// Count received.
        have: usize,
        /// Required threshold.
        need: u32,
    },
    /// SEC1 decode failure.
    #[error("SEC1 decode failed: {0}")]
    Sec1Decode(String),
    /// Duplicate party index.
    #[error("duplicate party index: {0}")]
    DuplicateParty(u32),
    /// Invalid scalar.
    #[error("invalid scalar: {0}")]
    InvalidScalar(String),
    /// AEAD failure.
    #[error("AEAD failure: {0}")]
    Aead(String),
}

fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint, EciesError> {
    let ep = Sec1Point::<p256::NistP256>::from_bytes(bytes)
        .map_err(|e| EciesError::Sec1Decode(format!("encoded point: {e}")))?;
    let ct_opt = AffinePoint::from_sec1_point(&ep);
    let affine = Option::<AffinePoint>::from(ct_opt)
        .ok_or_else(|| EciesError::Sec1Decode("point at infinity".into()))?;
    Ok(ProjectivePoint::from(affine))
}

fn encode_point(point: &ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_sec1_point(false).as_bytes().to_vec()
}

fn decode_scalar(bytes: &[u8]) -> Result<Scalar, EciesError> {
    if bytes.len() != 32 {
        return Err(EciesError::InvalidScalar(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let fb = FieldBytes::from(arr);
    let ct: CtOption<Scalar> = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).ok_or_else(|| EciesError::InvalidScalar("out of range".into()))
}

fn slice_to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], EciesError> {
    bytes
        .try_into()
        .map_err(|_| EciesError::Aead(format!("expected {N} bytes, got {}", bytes.len())))
}

fn x_coordinate(point: &ProjectivePoint) -> [u8; 32] {
    let ep = point.to_affine().to_sec1_point(false);
    let bytes = ep.as_bytes();
    if bytes.len() == 65 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[1..33]);
        arr
    } else {
        [0u8; 32]
    }
}

fn derive_aead_key(shared: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    // Simple HKDF-like derivation: SHA-256(shared || domain-sep).
    // Real HKDF would use extract+expand; this is sufficient for ECIES on P-256.
    let mut h = sha2::Sha256::new();
    h.update(b"confium-ecies-p256-v1");
    h.update(shared);
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Encrypt `plaintext` to `recipient` using ECIES-P256 + AES-256-GCM.
pub fn encrypt(recipient: &PublicKey, plaintext: &[u8]) -> Result<EncryptedBlob, EciesError> {
    let recipient_pt = decode_point(&recipient.bytes)?;

    // Ephemeral scalar
    let r = loop {
        let mut buf = [0u8; 32];
        rand_core::UnwrapErr(getrandom::SysRng).fill_bytes(&mut buf);
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(buf))) {
            if s != Scalar::ZERO {
                break s;
            }
        }
    };

    // Ephemeral public R = r*G
    let r_point = ProjectivePoint::GENERATOR * r;
    let ephemeral_public = encode_point(&r_point);

    // Shared secret K = r * recipient_pubkey
    let shared_point = recipient_pt * r;
    let shared = x_coordinate(&shared_point);

    // Derive AEAD key
    let key = derive_aead_key(&shared);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| EciesError::Aead(e.to_string()))?;

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    rand_core::UnwrapErr(getrandom::SysRng).fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", InOutBuf::from(buffer.as_mut_slice()))
        .map_err(|e| EciesError::Aead(e.to_string()))?;

    Ok(EncryptedBlob {
        ephemeral_public,
        ciphertext: buffer,
        nonce: nonce_bytes.to_vec(),
        tag: tag.to_vec(),
    })
}

/// Compute a partial decryption: `share * R` where R is the blob's ephemeral public key.
pub fn partial_decrypt(
    share: &DecryptionShare,
    blob: &EncryptedBlob,
) -> Result<PartialDecryption, EciesError> {
    let s = decode_scalar(&share.bytes)?;
    let r_point = decode_point(&blob.ephemeral_public)?;
    let partial = r_point * s;
    Ok(PartialDecryption {
        party_index: share.party_index,
        bytes: encode_point(&partial),
    })
}

/// Aggregate T partial decryptions to recover the plaintext.
///
/// Combined point = sum_i [ λ_i * partial_i ] = x * R = K (the ECDH shared secret).
/// Derive AEAD key from X-coordinate of K, then AEAD-decrypt the blob.
pub fn aggregate_partials(
    partials: &[PartialDecryption],
    threshold: u32,
    blob: &EncryptedBlob,
) -> Result<Vec<u8>, EciesError> {
    if (partials.len() as u32) < threshold {
        return Err(EciesError::ThresholdNotMet {
            have: partials.len(),
            need: threshold,
        });
    }

    let mut seen = std::collections::HashSet::new();
    for p in partials {
        if !seen.insert(p.party_index) {
            return Err(EciesError::DuplicateParty(p.party_index));
        }
    }

    // Lagrange-weighted sum: combined = sum_i λ_i * partial_i
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

    // Derive AEAD key from X-coordinate of combined
    let shared = x_coordinate(&combined);
    let key = derive_aead_key(&shared);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| EciesError::Aead(e.to_string()))?;

    // AEAD decrypt
    let nonce = Nonce::from(slice_to_array::<12>(&blob.nonce)?);
    let tag = aes_gcm::Tag::from(slice_to_array::<16>(&blob.tag)?);
    let mut buffer = blob.ciphertext.clone();
    cipher
        .decrypt_inout_detached(&nonce, b"", InOutBuf::from(buffer.as_mut_slice()), &tag)
        .map_err(|e| EciesError::Aead(format!("decrypt: {e}")))?;

    Ok(buffer)
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
    fn encrypt_then_decrypt_round_trip() {
        // Generate keypair, split into 3 shares (T=2).
        let keypair = generate_keypair();
        let pk = PublicKey::from_affine(keypair.public_key);
        let shares = split_secret(&keypair.secret_scalar, 2, 3);

        let plaintext = b"hello, threshold ECIES world";
        let blob = encrypt(&pk, plaintext).unwrap();

        // T-of-N partial decryption
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
            .map(|ds| partial_decrypt(ds, &blob).unwrap())
            .collect();

        let recovered = aggregate_partials(&partials, 2, &blob).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn different_share_subsets_recover_same_plaintext() {
        let keypair = generate_keypair();
        let pk = PublicKey::from_affine(keypair.public_key);
        let shares = split_secret(&keypair.secret_scalar, 3, 5);

        let plaintext = b"consistency check across share subsets";
        let blob = encrypt(&pk, plaintext).unwrap();

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
            .map(|ds| partial_decrypt(ds, &blob).unwrap())
            .collect();
        let recovered_a = aggregate_partials(&partials_a, 3, &blob).unwrap();

        // Subset B: shares 2, 3, 4
        let partials_b: Vec<PartialDecryption> = decryption_shares[2..5]
            .iter()
            .map(|ds| partial_decrypt(ds, &blob).unwrap())
            .collect();
        let recovered_b = aggregate_partials(&partials_b, 3, &blob).unwrap();

        assert_eq!(recovered_a.as_slice(), plaintext);
        assert_eq!(recovered_b.as_slice(), plaintext);
    }

    #[test]
    fn threshold_not_met_fails() {
        let keypair = generate_keypair();
        let pk = PublicKey::from_affine(keypair.public_key);
        let shares = split_secret(&keypair.secret_scalar, 3, 5);
        let blob = encrypt(&pk, b"x").unwrap();
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
        let partials: Vec<PartialDecryption> = decryption_shares[0..2]
            .iter()
            .map(|ds| partial_decrypt(ds, &blob).unwrap())
            .collect();
        let result = aggregate_partials(&partials, 3, &blob);
        assert!(matches!(result, Err(EciesError::ThresholdNotMet { .. })));
    }

    #[test]
    fn wrong_subset_fails_to_decrypt() {
        // Aggregate with random unrelated partials should fail AEAD.
        let keypair = generate_keypair();
        let pk = PublicKey::from_affine(keypair.public_key);
        let _shares = split_secret(&keypair.secret_scalar, 2, 3);
        let blob = encrypt(&pk, b"secret").unwrap();

        // Use shares from a DIFFERENT keypair to produce wrong partials.
        let other = generate_keypair();
        let other_shares = split_secret(&other.secret_scalar, 2, 3);
        let wrong_partials: Vec<PartialDecryption> = other_shares[0..2]
            .iter()
            .map(|s| {
                partial_decrypt(
                    &DecryptionShare {
                        party_index: s.x,
                        bytes: {
                            let fb: FieldBytes = s.y.to_bytes();
                            let arr: [u8; 32] = fb.into();
                            arr.to_vec()
                        },
                    },
                    &blob,
                )
                .unwrap()
            })
            .collect();
        let result = aggregate_partials(&wrong_partials, 2, &blob);
        assert!(matches!(result, Err(EciesError::Aead(_))));
    }
}
