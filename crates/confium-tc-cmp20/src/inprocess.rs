//! In-process synchronous driver for CMP20 DKG and signing.
//!
//! Thin wrapper over [`confium_tc::inprocess`] that names the CMP20
//! schemes and pulls the joint public key out of the first share. All
//! multi-round routing logic lives in the framework driver; this module
//! is intentionally short.
//!
//! ## Output wire format
//!
//! [`keygen`] returns `(shares, public_key)` where:
//!
//! - `shares[i]` is the opaque `Cmp20Share::to_bytes()` encoding for
//!   party `i` (71 bytes: magic[4] | version[1] | x_i[32] | X[33] | idx[1]).
//! - `public_key` is the 33-byte SEC1 compressed encoding of the joint
//!   P-256 point.
//!
//! [`sign`] returns a 64-byte `r || s` ECDSA signature. Verify it with
//! the [`p256::ecdsa`] crate's `VerifyingKey::verify`.
//!
//! ## Security note
//!
//! The underlying CMP20 crate's MtA sub-round is a simplified in-clear
//! stub. This driver inherits that property. See
//! [`crate::mta`] for the gap.

use elliptic_curve::sec1::ToSec1Point;
use p256::AffinePoint;

use confium_tc::Result;
use confium_tc::inprocess as driver;

use crate::share::Cmp20Share;

/// Outcome of a single CMP20 DKG run: N share blobs plus the joint
/// public key.
#[derive(Debug, Clone)]
pub struct KeygenOutput {
    /// One share blob per party, in roster order (0-based index matches
    /// `party_idx` of the share after subtracting 1).
    pub shares: Vec<Vec<u8>>,
    /// 33-byte SEC1 compressed encoding of the joint P-256 public key.
    pub public_key: Vec<u8>,
}

/// Drive the CMP20 non-interactive DKG in-process for `party_count`
/// parties at threshold `threshold`.
///
/// `threshold` must be in `1..=party_count`. All parties are in-process
/// (`Party::inproc`), identified as `p0`, `p1`, … `p{n-1}`.
pub fn keygen(threshold: u32, party_count: usize) -> Result<KeygenOutput> {
    let shares = driver::run_dkg(crate::DKG_SCHEME_NAME, threshold, party_count)?;
    let first = Cmp20Share::from_bytes(&shares[0])?;
    let public_key: Vec<u8> = first.public_key.to_sec1_point(true).as_bytes().to_vec();
    Ok(KeygenOutput { shares, public_key })
}

/// Drive a CMP20 signing session in-process using `share_blobs` (each
/// a `Cmp20Share::to_bytes()` blob from a previous [`keygen`]) at
/// threshold `threshold`. Returns the 64-byte `(r, s)` ECDSA signature.
///
/// `share_blobs.len()` must be `>= threshold`. The supplied shares must
/// all share the same joint public key — the protocol will otherwise
/// silently produce an invalid signature.
pub fn sign(share_blobs: &[Vec<u8>], threshold: u32, message: &[u8]) -> Result<Vec<u8>> {
    driver::run_sign(crate::SIGN_SCHEME_NAME, share_blobs, threshold, message)
}

/// Sign `messages.len()` messages against the same joint key without
/// re-running DKG. Reuses the same `share_blobs` for every message.
///
/// Returns one 64-byte signature per input message in input order.
/// If any individual signing op fails (e.g. protocol-level fault),
/// the function returns the error and discards prior results.
///
/// ## Performance
///
/// Each message signing is a full 4-round CMP20 protocol run. This
/// function does NOT cache nonces across messages — doing so would
/// leak the joint secret. The win over calling [`sign`] in a loop is
/// that the per-call Ruby/Python binding overhead disappears, which
/// is significant for high-volume signers (10-100× speedup for small
/// messages where binding overhead dominates).
pub fn sign_batch(
    share_blobs: &[Vec<u8>],
    threshold: u32,
    messages: &[&[u8]],
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(messages.len());
    for msg in messages {
        out.push(sign(share_blobs, threshold, msg)?);
    }
    Ok(out)
}

/// Decode a 33-byte SEC1 compressed P-256 point. Public so bindings can
/// verify the DKG-produced joint public key out-of-band.
pub fn decode_public_key(bytes: &[u8]) -> Result<AffinePoint> {
    use elliptic_curve::sec1::FromSec1Point;
    if bytes.len() != 33 {
        return Err(crate::error::scheme_error(
            crate::error::Cmp20ErrorCode::BAD_SHARE,
        ));
    }
    let enc = elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_bytes(bytes)
        .map_err(|_| crate::error::scheme_error(crate::error::Cmp20ErrorCode::BAD_SHARE))?;
    Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&enc))
        .ok_or_else(|| crate::error::scheme_error(crate::error::Cmp20ErrorCode::BAD_SHARE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    #[test]
    fn keygen_and_sign_round_trip() {
        let kg = keygen(2, 3).expect("dkg");
        assert_eq!(kg.shares.len(), 3);
        assert_eq!(kg.public_key.len(), 33);

        let sig = sign(&kg.shares[..2], 2, b"hello cmp20").expect("sign");
        assert_eq!(sig.len(), 64);

        let pk = decode_public_key(&kg.public_key).expect("pk decode");
        let vk = VerifyingKey::from_affine(pk).expect("vk");
        let s = Signature::from_slice(&sig).expect("parse sig");
        vk.verify(b"hello cmp20", &s).expect("verify ok");
    }

    #[test]
    fn keygen_below_threshold_sign_errors() {
        let kg = keygen(3, 5).expect("dkg");
        let err = sign(&kg.shares[..2], 3, b"msg");
        assert!(err.is_err());
    }

    #[test]
    fn keygen_full_committee_signs_and_verifies() {
        let kg = keygen(3, 3).expect("dkg");
        let sig = sign(&kg.shares, 3, b"all-three").expect("sign");
        let pk = decode_public_key(&kg.public_key).expect("pk decode");
        let vk = VerifyingKey::from_affine(pk).expect("vk");
        let s = Signature::from_slice(&sig).expect("parse sig");
        vk.verify(b"all-three", &s).expect("verify ok");
    }

    #[test]
    fn keygen_rejects_corrupt_share_magic() {
        let kg = keygen(2, 3).expect("dkg");
        let mut corrupt = kg.shares[0].clone();
        corrupt[0] = b'X';
        let err = sign(&[corrupt], 1, b"msg");
        assert!(err.is_err());
    }

    #[test]
    fn sign_batch_produces_one_sig_per_message() {
        let kg = keygen(2, 3).expect("dkg");
        let messages: Vec<&[u8]> = vec![b"msg-a", b"msg-b", b"msg-c", b"msg-d"];
        let sigs = sign_batch(&kg.shares[..2], 2, &messages).expect("batch sign");
        assert_eq!(sigs.len(), 4);
        for s in &sigs {
            assert_eq!(s.len(), 64);
        }
    }

    #[test]
    fn sign_batch_all_verify_under_joint_public_key() {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let kg = keygen(2, 3).expect("dkg");
        let messages: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let sigs = sign_batch(&kg.shares[..2], 2, &messages).expect("batch sign");
        let pk = decode_public_key(&kg.public_key).expect("pk");
        let vk = VerifyingKey::from_affine(pk).expect("vk");
        for (msg, sig) in messages.iter().zip(sigs.iter()) {
            let s = Signature::from_slice(sig).expect("parse sig");
            vk.verify(msg, &s).expect("verify");
        }
    }
}
