//! Fuzz target: share envelope deserialization + verification.
//!
//! Exercises the ShareEnvelope JSON parser with arbitrary byte input.
//! The target must not panic on malformed JSON.

use confium_tc::share_envelope::ShareEnvelope;

fn share_envelope_target(data: &[u8]) {
    if let Ok(envelope) = ShareEnvelope::from_bytes(data) {
        let _ = envelope.verify(b"fuzz-test-key-not-secret-1234");
    }
}

fn main() {
    let empty_vec: Vec<u8> = Vec::new();
    let big_vec: Vec<u8> = vec![0xFF; 1024];
    let templates: Vec<&[u8]> = vec![
        br#"{"version":1,"scheme":"CMP20","quorum_id":"q","party_idx":1,"threshold":2,"party_count":3,"share_data":[0,0]}"#,
        b"{}",
        b"null",
        b"[1,2,3]",
        b"\"string\"",
        b"42",
        b"true",
        &empty_vec,
        &big_vec,
    ];

    for data in &templates {
        share_envelope_target(data);
    }

    let mut rng_data = vec![0u8; 256];
    for round in 0..100_000u64 {
        for (i, b) in rng_data.iter_mut().enumerate() {
            *b = ((round * 41 + i as u64 * 7) & 0xFF) as u8;
        }
        share_envelope_target(&rng_data);
    }
    println!("share_envelope: 100000+ rounds completed, no panics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_does_not_panic() {
        share_envelope_target(b"");
    }

    #[test]
    fn garbage_input_does_not_panic() {
        share_envelope_target(&[0xFF; 512]);
    }

    #[test]
    fn valid_json_wrong_shape_does_not_panic() {
        share_envelope_target(b"\"not an object\"");
    }
}
