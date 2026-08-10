//! Opaque handle to a party's portion of a distributed secret.
//!
//! In a threshold scheme the secret key is never reconstructed in one
//! place; instead each party holds a [`Share`]. After a DKG run each
//! party obtains a fresh [`Share`] plus the shared public key. For
//! signing sessions a pre-existing [`Share`] is loaded as input.
//!
//! The framework treats share bytes as opaque — the encoding is defined
//! by the scheme plugin. [`Share`] carries the scheme name so a share
//! can only be fed back into a session of the same scheme.

use snafu::ensure;

use crate::Result;
use crate::error;

/// A party's share of a distributed secret.
///
/// `scheme` ties the share to the scheme that produced it (e.g.
/// `"FROST-ed25519"`). `bytes` is the scheme-specific encoding of the
/// share; the framework never inspects or reinterprets it.
///
/// The secret `bytes` field is zeroized on drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    scheme: String,
    bytes: Vec<u8>,
}

impl Drop for Share {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

impl Share {
    pub fn new(scheme: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Share {
            scheme: scheme.into(),
            bytes: bytes.into(),
        }
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Reject a share whose scheme doesn't match the session's scheme.
    /// Used by [`crate::session::Session::create`] when a pre-existing
    /// share is supplied as input.
    pub fn assert_scheme(&self, expected: &str) -> Result<()> {
        ensure!(
            self.scheme == expected,
            error::ShareSchemeMismatchSnafu {
                expected,
                actual: self.scheme.as_str(),
            }
        );
        Ok(())
    }

    /// Serialize into the `(scheme_len: u32 BE | scheme_utf8 | bytes)`
    /// framing used by [`Share::from_bytes`]. The scheme name is the
    /// canonical identifier; `bytes` is the scheme-specific payload.
    /// This is the only (de)serialization the framework needs — share
    /// persistence goes through [`crate::store`] using this encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let scheme_bytes = self.scheme.as_bytes();
        let mut out = Vec::with_capacity(4 + scheme_bytes.len() + self.bytes.len());
        out.extend_from_slice(&(scheme_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(scheme_bytes);
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parse the framing produced by [`Share::to_bytes`].
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(error::ShareTruncatedSnafu {
                needed: 4usize,
                have: data.len(),
            }
            .build());
        }
        let scheme_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let scheme_end = 4usize.checked_add(scheme_len).ok_or_else(|| {
            error::ShareTruncatedSnafu {
                needed: 4 + scheme_len,
                have: data.len(),
            }
            .build()
        })?;
        if data.len() < scheme_end {
            return Err(error::ShareTruncatedSnafu {
                needed: scheme_end,
                have: data.len(),
            }
            .build());
        }
        let scheme = std::str::from_utf8(&data[4..scheme_end])
            .map_err(|_| error::ShareInvalidSchemeSnafu {}.build())?
            .to_string();
        let bytes = data[scheme_end..].to_vec();
        Ok(Share { scheme, bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_round_trip() {
        let original = Share::new("FROST-ed25519", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = original.to_bytes();
        let decoded = Share::from_bytes(&encoded).expect("decode succeeds");
        assert_eq!(original, decoded);
    }

    #[test]
    fn share_round_trip_preserves_scheme_name() {
        let original = Share::new("GG18-ECDSA-P256", vec![1, 2, 3, 4, 5]);
        let encoded = original.to_bytes();
        let decoded = Share::from_bytes(&encoded).expect("decode succeeds");
        assert_eq!(decoded.scheme(), "GG18-ECDSA-P256");
        assert_eq!(decoded.bytes(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn share_round_trip_empty_bytes() {
        let original = Share::new("test-scheme", Vec::new());
        let encoded = original.to_bytes();
        let decoded = Share::from_bytes(&encoded).expect("decode succeeds");
        assert_eq!(original, decoded);
        assert!(decoded.is_empty());
    }

    #[test]
    fn share_from_bytes_rejects_truncated_header() {
        let err = Share::from_bytes(&[1, 2]).unwrap_err();
        assert!(matches!(err, error::Error::ShareTruncated { .. }));
    }

    #[test]
    fn share_from_bytes_rejects_truncated_scheme() {
        // scheme_len = 10 but only 2 bytes follow
        let data = [0, 0, 0, 10, b'a', b'b'];
        let err = Share::from_bytes(&data).unwrap_err();
        assert!(matches!(err, error::Error::ShareTruncated { .. }));
    }

    #[test]
    fn share_assert_scheme_accepts_match() {
        let share = Share::new("FROST-ed25519", vec![1]);
        share.assert_scheme("FROST-ed25519").expect("match is ok");
    }

    #[test]
    fn share_assert_scheme_rejects_mismatch() {
        let share = Share::new("FROST-ed25519", vec![1]);
        let err = share.assert_scheme("GG18-ECDSA-P256").unwrap_err();
        assert!(matches!(err, error::Error::ShareSchemeMismatch { .. }));
    }

    #[test]
    fn share_into_bytes_consumes_payload() {
        let share = Share::new("s", vec![9, 9, 9]);
        let bytes = share.into_bytes();
        assert_eq!(bytes, vec![9, 9, 9]);
    }
}
