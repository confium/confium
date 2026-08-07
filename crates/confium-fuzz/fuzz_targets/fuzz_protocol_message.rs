//! Fuzz target: coordinator protocol message deserialization.
//!
//! Exercises the TCP protocol message JSON parser with arbitrary bytes.
//! The target must not panic on malformed JSON.

use confium_tc::coordinator::net::ProtocolMessage;

fn protocol_message_target(data: &[u8]) {
    if let Ok(msg) = serde_json::from_slice::<ProtocolMessage>(data) {
        let _ = format!("{msg:?}");
    }
}

fn main() {
    let templates: Vec<Vec<u8>> = vec![
        br#"{"type":"HealthCheck"}"#.to_vec(),
        br#"{"type":"Register","signer_id":"a","quorum_id":"q"}"#.to_vec(),
        br#"{"type":"Error","message":"test"}"#.to_vec(),
        b"{}".to_vec(),
        b"null".to_vec(),
        b"[1,2]".to_vec(),
        b"\"x\"".to_vec(),
        b"42".to_vec(),
        Vec::new(),
        vec![0xFF; 1024],
    ];

    for data in &templates {
        protocol_message_target(data);
    }

    let mut rng_data = vec![0u8; 256];
    for round in 0..100_000u64 {
        for (i, b) in rng_data.iter_mut().enumerate() {
            *b = ((round * 29 + i as u64 * 11) & 0xFF) as u8;
        }
        protocol_message_target(&rng_data);
    }
    println!("protocol_message: 100000+ rounds completed, no panics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_does_not_panic() {
        protocol_message_target(b"");
    }

    #[test]
    fn garbage_does_not_panic() {
        protocol_message_target(&[0xFF; 256]);
    }

    #[test]
    fn valid_message_does_not_panic() {
        protocol_message_target(br#"{"type":"HealthCheck"}"#);
    }
}
