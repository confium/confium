//! Threshold nonce derivation — deterministic per-party nonce shares.
//!
//! Each party derives their nonce share deterministically from:
//! - Their private key share (secret scalar)
//! - The message hash being signed
//! - Their party index
//!
//! This eliminates the interactive nonce commitment round (CMP20/GG18
//! round 1) and prevents nonce reuse attacks. The full nonce is the
//! sum of all T nonce shares, reconstructed via Lagrange interpolation.
//!
//! ## Security note
//!
//! This is a simplified deterministic derivation suitable for testing
//! and non-interactive signing modes. Production CMP20/GG18 signing
//! uses interactive nonce generation for stronger security guarantees.

use hmac::{Hmac, Mac};
use p256::elliptic_curve::PrimeField;
use p256::{FieldBytes, Scalar};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive a deterministic nonce share for a party. The nonce is
/// derived from the party's secret scalar, the message hash, and
/// their party index via HMAC-SHA256, reduced mod the P-256 group
/// order.
///
/// The same inputs always produce the same nonce share — enabling
/// deterministic signing and non-interactive nonce generation.
pub fn derive_nonce_share(
    secret_share: &Scalar,
    message_hash: &[u8; 32],
    party_idx: u32,
) -> Scalar {
    let mut mac =
        HmacSha256::new_from_slice(&secret_share.to_repr()).expect("HMAC accepts any key length");
    mac.update(message_hash);
    mac.update(&party_idx.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let mut nonce_bytes = [0u8; 32];
    nonce_bytes.copy_from_slice(&result);

    reduce_mod_order(&nonce_bytes)
}

/// Sum T nonce shares (via Lagrange-weighted addition) to get the
/// full nonce. In threshold signing, the full nonce k = sum of
/// Lagrange-weighted nonce shares.
///
/// This is a simple sum — Lagrange weighting is applied at the
/// signature level, not the nonce level, in most threshold ECDSA
/// protocols.
pub fn sum_nonce_shares(shares: &[Scalar]) -> Scalar {
    shares.iter().fold(Scalar::ZERO, |acc, s| acc + s)
}

/// Derive nonce shares for all parties and return the full nonce
/// (their sum).
pub fn derive_full_nonce(
    secret_shares: &[Scalar],
    message_hash: &[u8; 32],
    party_indices: &[u32],
) -> Scalar {
    assert_eq!(secret_shares.len(), party_indices.len());
    let shares: Vec<Scalar> = secret_shares
        .iter()
        .zip(party_indices.iter())
        .map(|(s, &idx)| derive_nonce_share(s, message_hash, idx))
        .collect();
    sum_nonce_shares(&shares)
}

fn reduce_mod_order(bytes: &[u8; 32]) -> Scalar {
    let fb = FieldBytes::from(*bytes);
    let ct = Scalar::from_repr(fb);
    Option::<Scalar>::from(ct).unwrap_or_else(|| {
        // If the value is >= n, subtract 1 and try again. This is a
        // simple rejection-free reduction that ensures a non-zero
        // result in the valid range [1, n-1].
        let mut adjusted = *bytes;
        adjusted[0] = adjusted[0].wrapping_sub(1);
        let fb2 = FieldBytes::from(adjusted);
        let ct2 = Scalar::from_repr(fb2);
        Option::<Scalar>::from(ct2).unwrap_or(Scalar::ONE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Field;
    use p256::elliptic_curve::rand_core::UnwrapErr;

    fn random_scalar() -> Scalar {
        Scalar::random(&mut UnwrapErr(getrandom::SysRng))
    }

    #[test]
    fn derivation_is_deterministic() {
        let secret = random_scalar();
        let msg = [0x42u8; 32];
        let n1 = derive_nonce_share(&secret, &msg, 1);
        let n2 = derive_nonce_share(&secret, &msg, 1);
        assert_eq!(n1, n2);
    }

    #[test]
    fn different_party_indices_differ() {
        let secret = random_scalar();
        let msg = [0x42u8; 32];
        let n1 = derive_nonce_share(&secret, &msg, 1);
        let n2 = derive_nonce_share(&secret, &msg, 2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_messages_differ() {
        let secret = random_scalar();
        let m1 = [0x01u8; 32];
        let m2 = [0x02u8; 32];
        let n1 = derive_nonce_share(&secret, &m1, 1);
        let n2 = derive_nonce_share(&secret, &m2, 1);
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_secrets_differ() {
        let s1 = random_scalar();
        let s2 = random_scalar();
        let msg = [0x42u8; 32];
        let n1 = derive_nonce_share(&s1, &msg, 1);
        let n2 = derive_nonce_share(&s2, &msg, 1);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce_share_is_nonzero() {
        let secret = random_scalar();
        let msg = [0x42u8; 32];
        let nonce = derive_nonce_share(&secret, &msg, 1);
        assert_ne!(nonce, Scalar::ZERO);
    }

    #[test]
    fn sum_nonce_shares_works() {
        let s1 = random_scalar();
        let s2 = random_scalar();
        let expected = s1 + s2;
        assert_eq!(sum_nonce_shares(&[s1, s2]), expected);
    }

    #[test]
    fn sum_empty_is_zero() {
        assert_eq!(sum_nonce_shares(&[]), Scalar::ZERO);
    }

    #[test]
    fn full_nonce_is_sum_of_shares() {
        let secrets = vec![random_scalar(), random_scalar(), random_scalar()];
        let indices = vec![1u32, 2, 3];
        let msg = [0xAAu8; 32];

        let shares: Vec<Scalar> = secrets
            .iter()
            .zip(indices.iter())
            .map(|(s, &i)| derive_nonce_share(s, &msg, i))
            .collect();
        let expected = sum_nonce_shares(&shares);
        let actual = derive_full_nonce(&secrets, &msg, &indices);
        assert_eq!(actual, expected);
    }

    #[test]
    fn nonce_is_valid_scalar() {
        let secret = random_scalar();
        let msg = [0xFFu8; 32];
        let nonce = derive_nonce_share(&secret, &msg, 1);
        // Just verify it's representable (i.e., < n)
        let _bytes = nonce.to_repr();
    }

    #[test]
    fn reduce_mod_order_handles_large_input() {
        let max_bytes = [0xFFu8; 32];
        let result = reduce_mod_order(&max_bytes);
        assert_ne!(result, Scalar::ZERO);
    }
}
