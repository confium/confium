//! Fuzz target: COSE_Sign1 (RFC 8152) CBOR decoder.
//!
//! Exercises `CoseSign1::decode` with arbitrary bytes. The decoder
//! must not panic on any input — malformed CBOR surfaces as a
//! `CoseError`, not a panic. Of particular interest: adversarial
//! length headers (a byte-string length near `u64::MAX` previously
//! overflowed the bounds check — see the checked_add fix in
//! `CborReader::read_bytes`).

use confium_composite::cose::CoseSign1;

fn cose_decode_target(data: &[u8]) {
    let _ = CoseSign1::decode(data);
}

fn main() {
    let mut rng_data = vec![0u8; 256];
    for round in 0..100_000u64 {
        for (i, b) in rng_data.iter_mut().enumerate() {
            *b = ((round * 43 + i as u64 * 29) & 0xFF) as u8;
        }
        cose_decode_target(&rng_data);
    }
    println!("cose_decode: 100000 rounds completed, no panics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_does_not_panic() {
        cose_decode_target(&[]);
    }

    #[test]
    fn adversarial_length_headers_do_not_panic() {
        // Byte-string (major 2) with u64::MAX length.
        cose_decode_target(&[0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Text-string (major 3) with u64::MAX length.
        cose_decode_target(&[0x7B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Array (major 4) with u64::MAX count.
        cose_decode_target(&[0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Map (major 5) with u64::MAX count.
        cose_decode_target(&[0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn valid_cose_decodes() {
        let cose = CoseSign1::new(confium_composite::cose::alg::ED25519, b"m", b"s").unwrap();
        let encoded = cose.encode().unwrap();
        let _ = CoseSign1::decode(&encoded).unwrap();
        cose_decode_target(&encoded);
    }

    #[test]
    fn truncated_valid_cose_does_not_panic() {
        let cose = CoseSign1::new(confium_composite::cose::alg::ED25519, b"m", b"s").unwrap();
        let encoded = cose.encode().unwrap();
        for len in 0..encoded.len() {
            cose_decode_target(&encoded[..len]);
        }
    }
}
