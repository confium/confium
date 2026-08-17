//! Per-party share material produced by GG18 DKG and consumed by signing.

use elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, FieldBytes, NonZeroScalar, Scalar};
use zeroize::Zeroize;

use crate::error::{Gg18ErrorCode, Result, scheme_error};

const SHARE_MAGIC: [u8; 4] = *b"GG18";
const SHARE_VERSION: u8 = 1;
/// Wire length: magic[4] | version[1] | x_i[32] | X[33] | idx[1].
pub const SHARE_BYTES: usize = 4 + 1 + 32 + 33 + 1;

/// One party's durable GG18 secret material.
#[derive(Clone)]
pub struct Gg18Share {
    /// This party's Shamir share of the joint secret.
    pub x_i: NonZeroScalar,
    /// The shared public key `X = g^x` (affine).
    pub public_key: AffinePoint,
    /// 1-based DKG roster index of this party.
    pub party_idx: u32,
}

impl std::fmt::Debug for Gg18Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gg18Share")
            .field("x_i", &"<redacted>")
            .field("party_idx", &self.party_idx)
            .finish_non_exhaustive()
    }
}

impl Drop for Gg18Share {
    fn drop(&mut self) {
        let mut bytes = self.x_i.to_bytes();
        bytes.zeroize();
    }
}

impl Gg18Share {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SHARE_BYTES);
        out.extend_from_slice(&SHARE_MAGIC);
        out.push(SHARE_VERSION);
        out.extend_from_slice(&self.x_i.to_bytes());
        out.extend_from_slice(self.public_key.to_sec1_point(true).as_bytes());
        out.push(self.party_idx as u8);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != SHARE_BYTES {
            return Err(scheme_error(Gg18ErrorCode::BAD_SHARE));
        }
        if data[0..4] != SHARE_MAGIC {
            return Err(scheme_error(Gg18ErrorCode::BAD_SHARE));
        }
        if data[4] != SHARE_VERSION {
            return Err(scheme_error(Gg18ErrorCode::BAD_SHARE));
        }
        let mut x_i_bytes = [0u8; 32];
        x_i_bytes.copy_from_slice(&data[5..37]);
        let fb: FieldBytes = x_i_bytes.into();
        let x_i: NonZeroScalar = Option::from(NonZeroScalar::from_repr(fb))
            .ok_or_else(|| scheme_error(Gg18ErrorCode::BAD_SHARE))?;
        let pk_bytes = &data[37..70];
        let public_key = decode_affine(pk_bytes)?;
        let party_idx = data[70] as u32;
        Ok(Gg18Share {
            x_i,
            public_key,
            party_idx,
        })
    }

    pub fn from_parts(x_i: NonZeroScalar, public_key: AffinePoint, party_idx: u32) -> Self {
        Gg18Share {
            x_i,
            public_key,
            party_idx,
        }
    }

    pub fn scalar(&self) -> Scalar {
        *self.x_i
    }
}

/// Decode a 33-byte SEC1 compressed point into an [`AffinePoint`].
pub(crate) fn decode_affine(bytes: &[u8]) -> Result<AffinePoint> {
    use elliptic_curve::point::AffineCoordinates;
    use elliptic_curve::sec1::FromSec1Point;
    if bytes.len() != 33 {
        return Err(scheme_error(Gg18ErrorCode::BAD_SHARE));
    }
    let enc = elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_bytes(bytes)
        .map_err(|_| scheme_error(Gg18ErrorCode::BAD_SHARE))?;
    let pt: AffinePoint = Option::from(AffinePoint::from_sec1_point(&enc))
        .ok_or_else(|| scheme_error(Gg18ErrorCode::BAD_SHARE))?;
    let _ = pt.x();
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::Generate;

    fn random_share(idx: u32) -> Gg18Share {
        let x_i = NonZeroScalar::generate();
        let g = p256::ProjectivePoint::GENERATOR;
        let pk = (g * *x_i).to_affine();
        Gg18Share::from_parts(x_i, pk, idx)
    }

    #[test]
    fn share_round_trip() {
        let s = random_share(1);
        let bytes = s.to_bytes();
        assert_eq!(bytes.len(), SHARE_BYTES);
        let s2 = Gg18Share::from_bytes(&bytes).expect("decode");
        assert_eq!(s2.party_idx, 1);
        assert_eq!(s2.x_i.to_bytes(), s.x_i.to_bytes());
    }

    #[test]
    fn share_rejects_bad_magic() {
        let mut bytes = random_share(0).to_bytes();
        bytes[0] = b'X';
        assert!(Gg18Share::from_bytes(&bytes).is_err());
    }

    #[test]
    fn share_rejects_truncated() {
        let bytes = random_share(0).to_bytes();
        assert!(Gg18Share::from_bytes(&bytes[..10]).is_err());
    }

    #[test]
    fn share_rejects_zero_scalar() {
        let mut bytes = random_share(0).to_bytes();
        for b in &mut bytes[5..37] {
            *b = 0;
        }
        assert!(Gg18Share::from_bytes(&bytes).is_err());
    }

    #[test]
    fn debug_redacts_secret() {
        let s = random_share(0);
        let dbg = format!("{:?}", s);
        assert!(dbg.contains("<redacted>"));
    }
}
