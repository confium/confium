//! Group primitives for FROST over ed25519.
//!
//! FROST (draft-irtf-cfrg-frost) is defined generically over a prime-order
//! group. The "ed25519" instantiation works in the ristretto255-free
//! Edwards form factor used by RFC 8032 ed25519 signatures so that the
//! aggregate signature verifies under any standard ed25519 verifier
//! (e.g. `ed25519-dalek`, libsodium, Go's `crypto/ed25519`).
//!
//! Scalars are 32-byte little-endian values reduced modulo the group
//! order `ℓ = 2^252 + 27742317777372353535851937790883648493`. Group
//! elements are Edwards points; their wire form is the 32-byte
//! compressed-Y encoding (`CompressedEdwardsY`) used by ed25519 keys and
//! signatures.
//!
//! All FROST math is scalar / point arithmetic in this group; this module
//! adds nothing cryptographically — it just pins the right curve types
//! and serialization.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::error::{CODE_INVALID_COMMITMENT, CODE_MALFORMED_SHARE, FrostError, Result};

/// Byte length of a scalar in its canonical wire encoding.
pub const SCALAR_BYTES: usize = 32;

/// Byte length of a compressed group element (commitment, public key).
pub const ELEMENT_BYTES: usize = 32;

/// The base point B used throughout FROST and ed25519.
#[inline]
pub fn base_point() -> EdwardsPoint {
    ED25519_BASEPOINT_POINT
}

/// Multiply the base point B by a scalar — `s·B`.
#[inline]
pub fn mul_base(s: &Scalar) -> EdwardsPoint {
    EdwardsPoint::mul_base(s)
}

/// Encode a scalar to its 32-byte little-endian wire form.
#[inline]
pub fn scalar_to_bytes(s: &Scalar) -> [u8; SCALAR_BYTES] {
    s.to_bytes()
}

/// Decode a scalar from 32 bytes, reducing mod ℓ. Used for inputs like
/// the local share where the encoding may have come from a wide hash.
pub fn scalar_from_bytes_mod_order(bytes: &[u8; SCALAR_BYTES]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

/// Decode a scalar from a slice, validating length.
pub fn scalar_from_slice(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != SCALAR_BYTES {
        return Err(FrostError::MalformedShare {
            reason: "scalar must be exactly 32 bytes",
            code: CODE_MALFORMED_SHARE,
        });
    }
    let mut arr = [0u8; SCALAR_BYTES];
    arr.copy_from_slice(bytes);
    Ok(scalar_from_bytes_mod_order(&arr))
}

/// Compress a point to its 32-byte wire form.
#[inline]
pub fn point_to_bytes(p: &EdwardsPoint) -> [u8; ELEMENT_BYTES] {
    p.compress().to_bytes()
}

/// Decompress a 32-byte encoded point. Returns `None` if the encoding is
/// not a valid point on the curve.
pub fn point_from_bytes(bytes: &[u8; ELEMENT_BYTES]) -> Option<EdwardsPoint> {
    CompressedEdwardsY::from_slice(bytes).ok()?.decompress()
}

/// Decompress a point from a slice, validating both length and curve
/// membership.
pub fn point_from_slice(bytes: &[u8], party: &str) -> Result<EdwardsPoint> {
    if bytes.len() != ELEMENT_BYTES {
        return Err(FrostError::InvalidCommitment {
            party: party.to_string(),
            reason: "commitment must be exactly 32 bytes",
            code: CODE_INVALID_COMMITMENT,
        });
    }
    let mut arr = [0u8; ELEMENT_BYTES];
    arr.copy_from_slice(bytes);
    point_from_bytes(&arr).ok_or(FrostError::InvalidCommitment {
        party: party.to_string(),
        reason: "encoded point is not a valid curve point",
        code: CODE_INVALID_COMMITMENT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_round_trip() {
        let s = Scalar::from_bytes_mod_order([42u8; 32]);
        let bytes = scalar_to_bytes(&s);
        let back = scalar_from_bytes_mod_order(&bytes);
        assert_eq!(s, back);
    }

    #[test]
    fn base_point_times_one_is_base() {
        let one = Scalar::ONE;
        assert_eq!(mul_base(&one), base_point());
    }

    #[test]
    fn point_round_trip_via_base() {
        let s = Scalar::from(123u64);
        let p = mul_base(&s);
        let bytes = point_to_bytes(&p);
        let back = point_from_bytes(&bytes).expect("round trips");
        assert_eq!(p, back);
    }

    #[test]
    fn point_from_slice_rejects_bad_length() {
        let err = point_from_slice(&[0u8; 31], "x").unwrap_err();
        match err {
            FrostError::InvalidCommitment { .. } => {}
            other => panic!("expected InvalidCommitment, got {other:?}"),
        }
    }

    #[test]
    fn point_from_slice_rejects_invalid_encoding() {
        // `[2u8; 32]` is a known off-curve encoding: Y=2 has no
        // corresponding x on the Edwards curve, so decompress fails.
        let err = point_from_slice(&[2u8; 32], "x").unwrap_err();
        match err {
            FrostError::InvalidCommitment { reason, .. } => {
                assert!(reason.contains("valid curve point"));
            }
            other => panic!("expected InvalidCommitment, got {other:?}"),
        }
    }
}
