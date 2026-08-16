//! COSE_Sign1 — CBOR-encoded signature wrapper (RFC 8152).
//!
//! Wraps a single signature in the COSE_Sign1 structure:
//!
//! ```text
//! COSE_Sign1 = [
//!     protected : bstr .cbor {1: algorithm},
//!     unprotected : {},
//!     payload : bstr,
//!     signature : bstr
//! ]
//! ```
//!
//! Used in IoT and edge computing for compact binary signatures.
//! The implementation uses a minimal CBOR encoder for the specific
//! COSE_Sign1 structure — no external CBOR dependency.

use serde::{Deserialize, Serialize};

/// CBOR tag for COSE_Sign1 (RFC 8152 §4.1).
pub const COSE_SIGN1_TAG: u64 = 18;

/// Standard COSE algorithm parameter key.
pub const COSE_ALG_PARAM: i32 = 1;

/// Algorithm identifiers (subset of IANA COSE Algorithms registry).
pub mod alg {
    /// EdDSA (Ed25519).
    pub const EDDSA: i32 = -8;
    /// ECDSA with SHA-256 over P-256.
    pub const ES256: i32 = -7;
    /// Ed25519 signature.
    pub const ED25519: i32 = -19;
}

/// A COSE_Sign1 structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoseSign1 {
    /// Protected header (CBOR-encoded, raw bytes).
    pub protected_bytes: Vec<u8>,
    /// Unprotected header (raw bytes, usually empty).
    pub unprotected_bytes: Vec<u8>,
    /// Payload (the message being signed).
    pub payload: Vec<u8>,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// Errors during COSE operations.
#[derive(Debug, thiserror::Error)]
pub enum CoseError {
    /// Encoding error.
    #[error("cbor encoding error: {0}")]
    Encode(String),
    /// Decoding error.
    #[error("cbor decoding error: {0}")]
    Decode(String),
}

impl CoseSign1 {
    /// Create a new COSE_Sign1 with a protected header containing
    /// the algorithm identifier.
    pub fn new(algorithm: i32, payload: &[u8], signature: &[u8]) -> Result<Self, CoseError> {
        let protected = encode_protected_header(algorithm)?;
        Ok(Self {
            protected_bytes: protected,
            unprotected_bytes: Vec::new(),
            payload: payload.to_vec(),
            signature: signature.to_vec(),
        })
    }

    /// Encode to CBOR bytes (tagged with COSE_SIGN1_TAG).
    pub fn encode(&self) -> Result<Vec<u8>, CoseError> {
        encode_cose_sign1(self)
    }

    /// Decode from CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CoseError> {
        decode_cose_sign1(bytes)
    }

    /// Extract the algorithm from the protected header.
    pub fn algorithm(&self) -> Result<i32, CoseError> {
        decode_algorithm(&self.protected_bytes)
    }
}

// Minimal CBOR encoder

const CBOR_MAJOR_UNSIGNED: u8 = 0;
const CBOR_MAJOR_BYTE_STRING: u8 = 2;
const CBOR_MAJOR_ARRAY: u8 = 4;
const CBOR_MAJOR_MAP: u8 = 5;

fn cbor_unsigned_int(n: u64) -> Vec<u8> {
    if n <= 23 {
        vec![(CBOR_MAJOR_UNSIGNED << 5) | n as u8]
    } else if n <= u8::MAX as u64 {
        let mut v = vec![(CBOR_MAJOR_UNSIGNED << 5) | 24];
        v.push(n as u8);
        v
    } else if n <= u16::MAX as u64 {
        let mut v = vec![(CBOR_MAJOR_UNSIGNED << 5) | 25];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    } else if n <= u32::MAX as u64 {
        let mut v = vec![(CBOR_MAJOR_UNSIGNED << 5) | 26];
        v.extend_from_slice(&(n as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![(CBOR_MAJOR_UNSIGNED << 5) | 27];
        v.extend_from_slice(&n.to_be_bytes());
        v
    }
}

fn cbor_negative_int(n: i64) -> Vec<u8> {
    // CBOR negative integer: value = -(1 + unsigned).
    // Encoded with major type 1, same info/length scheme as unsigned.
    let unsigned = (-(n as i128) - 1) as u64;
    if unsigned <= 23 {
        vec![(1u8 << 5) | unsigned as u8]
    } else if unsigned <= u8::MAX as u64 {
        let mut v = vec![(1u8 << 5) | 24];
        v.push(unsigned as u8);
        v
    } else if unsigned <= u16::MAX as u64 {
        let mut v = vec![(1u8 << 5) | 25];
        v.extend_from_slice(&(unsigned as u16).to_be_bytes());
        v
    } else if unsigned <= u32::MAX as u64 {
        let mut v = vec![(1u8 << 5) | 26];
        v.extend_from_slice(&(unsigned as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![(1u8 << 5) | 27];
        v.extend_from_slice(&unsigned.to_be_bytes());
        v
    }
}

fn cbor_byte_string(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let mut v = vec![(CBOR_MAJOR_BYTE_STRING << 5)];
    if len <= 23 {
        v[0] |= len as u8;
        v.extend_from_slice(bytes);
    } else if len <= u8::MAX as usize {
        v[0] |= 24;
        v.push(len as u8);
        v.extend_from_slice(bytes);
    } else if len <= u16::MAX as usize {
        v[0] |= 25;
        v.extend_from_slice(&(len as u16).to_be_bytes());
        v.extend_from_slice(bytes);
    } else {
        v[0] |= 26;
        v.extend_from_slice(&(len as u32).to_be_bytes());
        v.extend_from_slice(bytes);
    }
    v
}

fn cbor_array_header(count: usize) -> Vec<u8> {
    let mut v = vec![(CBOR_MAJOR_ARRAY << 5)];
    if count <= 23 {
        v[0] |= count as u8;
    } else if count <= u8::MAX as usize {
        v[0] |= 24;
        v.push(count as u8);
    } else {
        v[0] |= 25;
        v.extend_from_slice(&(count as u16).to_be_bytes());
    }
    v
}

fn cbor_map_header(count: usize) -> Vec<u8> {
    let mut v = vec![(CBOR_MAJOR_MAP << 5)];
    if count <= 23 {
        v[0] |= count as u8;
    } else {
        v[0] |= 24;
        v.push(count as u8);
    }
    v
}

fn encode_protected_header(alg: i32) -> Result<Vec<u8>, CoseError> {
    let mut buf = cbor_map_header(1);
    buf.extend(cbor_unsigned_int(COSE_ALG_PARAM as u64));
    if alg < 0 {
        buf.extend(cbor_negative_int(alg as i64));
    } else {
        buf.extend(cbor_unsigned_int(alg as u64));
    }
    Ok(buf)
}

fn encode_cose_sign1(cose: &CoseSign1) -> Result<Vec<u8>, CoseError> {
    let mut out = vec![];
    // Tag 18 as CBOR major type 6 (tag).
    // Major type 6 = 0xC0. For tag 18 (≤ 23): 0xC0 | 18 = 0xD2.
    out.push(0xC0 | COSE_SIGN1_TAG as u8);

    // Array of 4 elements.
    out.extend(cbor_array_header(4));

    // [0] protected header (bstr containing CBOR map)
    out.extend(cbor_byte_string(&cose.protected_bytes));
    // [1] unprotected header (bstr, usually empty map)
    out.extend(cbor_byte_string(&cose.unprotected_bytes));
    // [2] payload
    out.extend(cbor_byte_string(&cose.payload));
    // [3] signature
    out.extend(cbor_byte_string(&cose.signature));

    Ok(out)
}

// Minimal CBOR decoder

struct CborReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[allow(dead_code)]
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn read_u8(&mut self) -> Option<u8> {
        self.bytes.get(self.pos).map(|&b| {
            self.pos += 1;
            b
        })
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        // checked_add: an adversarial CBOR length near usize::MAX must
        // surface as a parse error, not an overflowing comparison that
        // wraps and slices out of bounds.
        let end = self.pos.checked_add(n)?;
        if end > self.bytes.len() {
            return None;
        }
        let result = &self.bytes[self.pos..end];
        self.pos = end;
        Some(result)
    }

    /// Sanity-check a declared array/map count against the remaining
    /// input: every CBOR item needs at least one byte, so a count
    /// larger than the bytes left can never be satisfied. Bounds the
    /// Vec allocation to the input size instead of trusting an
    /// adversarial length header (u64::MAX → capacity-overflow panic).
    fn check_count(&self, count: usize) -> Option<()> {
        if count > self.bytes.len() - self.pos {
            None
        } else {
            Some(())
        }
    }

    fn read(&mut self) -> Option<CborValue<'a>> {
        let initial = self.read_u8()?;
        let major = (initial & 0xE0) >> 5;
        let info = initial & 0x1F;

        match major {
            0 => {
                let n = self.read_uint(info)?;
                Some(CborValue::Unsigned(n))
            }
            1 => {
                let n = self.read_uint(info)?;
                Some(CborValue::Negative(n))
            }
            2 => {
                let len = self.read_uint(info)? as usize;
                let bytes = self.read_bytes(len)?;
                Some(CborValue::Bytes(bytes))
            }
            4 => {
                let count = self.read_uint(info)? as usize;
                self.check_count(count)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.read()?);
                }
                Some(CborValue::Array(items))
            }
            5 => {
                let count = self.read_uint(info)? as usize;
                self.check_count(count)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let k = self.read()?;
                    let v = self.read()?;
                    entries.push((k, v));
                }
                Some(CborValue::Map(entries))
            }
            6 => {
                // Tag: read the tag value, then the tagged item.
                let _tag = self.read_uint(info)?;
                self.read()
            }
            _ => None,
        }
    }

    fn read_uint(&mut self, info: u8) -> Option<u64> {
        match info {
            n if n <= 23 => Some(n as u64),
            24 => Some(self.read_u8()? as u64),
            25 => {
                let bytes = self.read_bytes(2)?;
                Some(u16::from_be_bytes(bytes.try_into().ok()?) as u64)
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                Some(u32::from_be_bytes(bytes.try_into().ok()?) as u64)
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                Some(u64::from_be_bytes(bytes.try_into().ok()?))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
enum CborValue<'a> {
    Unsigned(u64),
    Negative(u64),
    Bytes(&'a [u8]),
    Array(Vec<CborValue<'a>>),
    Map(Vec<(CborValue<'a>, CborValue<'a>)>),
}

fn decode_cose_sign1(bytes: &[u8]) -> Result<CoseSign1, CoseError> {
    // The CBOR reader transparently handles tags (major type 6):
    // read() returns the tagged item directly.
    let mut reader = CborReader::new(bytes);
    let array_value = reader
        .read()
        .ok_or_else(|| CoseError::Decode("empty".into()))?;
    decode_cose_sign1_array(&array_value, bytes)
}

fn decode_cose_sign1_array(value: &CborValue<'_>, _bytes: &[u8]) -> Result<CoseSign1, CoseError> {
    let items = match value {
        CborValue::Array(v) => v,
        _ => return Err(CoseError::Decode("expected array".into())),
    };
    if items.len() != 4 {
        return Err(CoseError::Decode("expected 4 elements".into()));
    }
    let protected = match &items[0] {
        CborValue::Bytes(b) => b.to_vec(),
        _ => return Err(CoseError::Decode("protected must be bstr".into())),
    };
    let unprotected = match &items[1] {
        CborValue::Bytes(b) => b.to_vec(),
        _ => return Err(CoseError::Decode("unprotected must be bstr".into())),
    };
    let payload = match &items[2] {
        CborValue::Bytes(b) => b.to_vec(),
        _ => return Err(CoseError::Decode("payload must be bstr".into())),
    };
    let signature = match &items[3] {
        CborValue::Bytes(b) => b.to_vec(),
        _ => return Err(CoseError::Decode("signature must be bstr".into())),
    };
    Ok(CoseSign1 {
        protected_bytes: protected,
        unprotected_bytes: unprotected,
        payload,
        signature,
    })
}

fn decode_algorithm(protected_bytes: &[u8]) -> Result<i32, CoseError> {
    let mut reader = CborReader::new(protected_bytes);
    let map = reader
        .read()
        .ok_or_else(|| CoseError::Decode("empty protected header".into()))?;
    let entries = match map {
        CborValue::Map(e) => e,
        _ => return Err(CoseError::Decode("protected header must be a map".into())),
    };
    for (k, v) in entries {
        if let CborValue::Unsigned(key) = k {
            if key == COSE_ALG_PARAM as u64 {
                match v {
                    CborValue::Unsigned(n) => return Ok(n as i32),
                    CborValue::Negative(n) => {
                        // CBOR negative: -(1 + n)
                        let neg = -((n as i64) + 1);
                        return Ok(neg as i32);
                    }
                    _ => {}
                }
            }
        }
    }
    Err(CoseError::Decode("algorithm not found".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_u64_max_length_is_error_not_panic() {
        // Byte-string header (major 2) with 8-byte length = u64::MAX.
        // The old `pos + n` comparison overflowed, wrapped, and sliced
        // out of bounds — a panic on adversarial input.
        let evil = [0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = std::panic::catch_unwind(|| CoseSign1::decode(&evil));
        assert!(
            result.is_ok(),
            "decoder must not panic on adversarial length"
        );
        assert!(result.unwrap().is_err(), "u64::MAX length must not decode");
    }

    #[test]
    fn adversarial_huge_length_at_offset_is_error_not_panic() {
        // Same, but positioned after some valid bytes so pos > 0 when
        // the overflowing length is read.
        let mut evil = vec![0x83, 0x01]; // array(3), unsigned(1)
        evil.extend_from_slice(&[0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]);
        let result = std::panic::catch_unwind(|| CoseSign1::decode(&evil));
        assert!(result.is_ok(), "decoder must not panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn truncated_input_is_error_not_panic() {
        for len in 0..8 {
            let truncated = &b"\xD2\x84\x43\x01\x02\x03\x04\xA0"[..len];
            assert!(CoseSign1::decode(truncated).is_err());
        }
    }

    #[test]
    fn create_and_extract_algorithm() {
        let cose = CoseSign1::new(alg::ES256, b"payload", b"signature").unwrap();
        assert_eq!(cose.algorithm().unwrap(), alg::ES256);
    }

    #[test]
    fn round_trip_preserves_payload_and_signature() {
        let original = CoseSign1::new(alg::ED25519, b"my payload", b"my sig").unwrap();
        let encoded = original.encode().unwrap();
        let decoded = CoseSign1::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, b"my payload");
        assert_eq!(decoded.signature, b"my sig");
    }

    #[test]
    fn cbor_unsigned_encoding_zero() {
        assert_eq!(cbor_unsigned_int(0), vec![0x00]);
    }

    #[test]
    fn cbor_unsigned_encoding_small() {
        assert_eq!(cbor_unsigned_int(23), vec![23]);
    }

    #[test]
    fn cbor_unsigned_encoding_one_byte() {
        assert_eq!(cbor_unsigned_int(200), vec![24, 200]);
    }

    #[test]
    fn cbor_byte_string_empty() {
        assert_eq!(cbor_byte_string(b""), vec![0x40]);
    }

    #[test]
    fn cbor_byte_string_short() {
        assert_eq!(cbor_byte_string(b"abc"), vec![0x43, b'a', b'b', b'c']);
    }

    #[test]
    fn negative_algorithm_encoding() {
        let cose = CoseSign1::new(alg::EDDSA, b"", b"").unwrap();
        assert_eq!(cose.algorithm().unwrap(), alg::EDDSA);
    }

    #[test]
    fn decode_empty_payload() {
        let cose = CoseSign1::new(alg::ES256, b"", b"sig").unwrap();
        let encoded = cose.encode().unwrap();
        let decoded = CoseSign1::decode(&encoded).unwrap();
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn decode_large_signature() {
        let sig = vec![0xAA; 256];
        let cose = CoseSign1::new(alg::ES256, b"msg", &sig).unwrap();
        let encoded = cose.encode().unwrap();
        let decoded = CoseSign1::decode(&encoded).unwrap();
        assert_eq!(decoded.signature, sig);
    }
}
