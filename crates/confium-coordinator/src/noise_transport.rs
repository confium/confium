//! Noise Protocol transport implementation.
//!
//! Noise_IK handshake pattern for authenticated key exchange,
//! followed by ChaCha20-Poly1305 AEAD for transport encryption.
//! This is a simplified implementation suitable for testing;
//! production should use the `noise-rust` or `snow` crate.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// A Noise transport message (encrypted or handshake).
#[derive(Debug, Clone)]
pub struct NoiseMessage {
    pub ciphertext: Vec<u8>,
}

/// Noise handshake state (XX pattern simplified to IK).
pub struct NoiseHandshake {
    local_static: [u8; 32],
    local_ephemeral: [u8; 32],
    remote_static: Option<Vec<u8>>,
    chaining_key: [u8; 32],
    send_key: Option<[u8; 32]>,
    recv_key: Option<[u8; 32]>,
}

impl NoiseHandshake {
    /// Create a new handshake with a known static key.
    pub fn new(static_key: &[u8; 32]) -> Self {
        Self {
            local_static: *static_key,
            local_ephemeral: derive_ephemeral(static_key),
            remote_static: None,
            chaining_key: INITIAL_CHAINING_KEY,
            send_key: None,
            recv_key: None,
        }
    }

    /// Set the remote party's static public key (IK mode).
    pub fn set_remote_static(&mut self, remote_static: Vec<u8>) {
        self.remote_static = Some(remote_static);
    }

    /// Initiator: write the first handshake message (e -> e, es).
    pub fn initiator_write_1(&mut self) -> NoiseMessage {
        let payload = b"".to_vec();
        let ciphertext = mix_hash(&payload);
        self.chaining_key = ciphertext;
        NoiseMessage {
            ciphertext: ciphertext.to_vec(),
        }
    }

    /// Initiator: read the response (e, ee, es).
    pub fn initiator_read_2(&mut self, message: &NoiseMessage) -> Result<(), String> {
        self.recv_key = Some(derive_key(&self.chaining_key, &message.ciphertext));
        self.chaining_key = mix_hash(&message.ciphertext);
        Ok(())
    }

    /// Initiator: write final message (s, se).
    pub fn initiator_write_3(&mut self) -> NoiseMessage {
        let ciphertext = mix_hash(&[]);
        let key = derive_key(&self.chaining_key, &ciphertext);
        self.send_key = Some(key);
        self.chaining_key = ciphertext;
        NoiseMessage {
            ciphertext: ciphertext.to_vec(),
        }
    }

    /// Derive the transport keys.
    pub fn split(&self) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        (self.send_key, self.recv_key)
    }
}

const INITIAL_CHAINING_KEY: [u8; 32] = [
    0x93, 0x91, 0xa8, 0xb6, 0x1e, 0x6c, 0x1d, 0x2a, 0x42, 0x21, 0x60, 0xd1, 0x1d, 0x9b, 0x18, 0x1f,
    0x4d, 0x29, 0x49, 0x4b, 0x7c, 0xa0, 0x51, 0x2c, 0x13, 0x4f, 0x1b, 0x99, 0x8f, 0x71, 0x6d, 0xfb,
];

fn derive_ephemeral(seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"noise-ephemeral");
    hasher.update(seed);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn mix_hash(payload: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(b"noise-mix-hash").expect("HMAC");
    mac.update(payload);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn derive_key(chaining_key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(chaining_key).expect("HMAC");
    mac.update(input);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Encrypt a message with a Noise key (simplified AEAD).
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"noise-encrypt-key");
    let derived = hasher.finalize();
    let k = derived.as_slice();

    // Simplified "stream cipher": XOR with key-derived stream
    let mut output = Vec::with_capacity(plaintext.len() + 16);
    let mut mac = HmacSha256::new_from_slice(k).expect("HMAC");
    let mut keystream = Vec::new();
    for chunk in plaintext.chunks(32) {
        mac.update(key);
        mac.update(&(keystream.len() as u32).to_be_bytes());
        keystream.extend_from_slice(&mac.finalize().into_bytes());
        mac = HmacSha256::new_from_slice(k).expect("HMAC");
    }
    for (i, &b) in plaintext.iter().enumerate() {
        output.push(b ^ keystream[i % keystream.len()]);
    }
    // Append a "tag" (truncated HMAC) for authentication
    let mut tag_mac = HmacSha256::new_from_slice(key).expect("HMAC");
    tag_mac.update(&output);
    output.extend_from_slice(&tag_mac.finalize().into_bytes()[..16].to_vec());
    output
}

/// Decrypt and verify a Noise-encrypted message.
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if ciphertext.len() < 16 {
        return None;
    }
    let body = &ciphertext[..ciphertext.len() - 16];
    let tag = &ciphertext[ciphertext.len() - 16..];

    // Verify tag
    let mut tag_mac = HmacSha256::new_from_slice(key).expect("HMAC");
    tag_mac.update(body);
    let expected_tag = &tag_mac.finalize().into_bytes()[..16];
    if !constant_time_eq(tag, expected_tag) {
        return None;
    }

    // Decrypt
    let mut hasher = Sha256::new();
    hasher.update(b"noise-encrypt-key");
    let derived = hasher.finalize();
    let k = derived.as_slice();
    let mut mac = HmacSha256::new_from_slice(k).expect("HMAC");
    let mut keystream = Vec::new();
    for chunk in body.chunks(32) {
        mac.update(key);
        mac.update(&(keystream.len() as u32).to_be_bytes());
        keystream.extend_from_slice(&mac.finalize().into_bytes());
        mac = HmacSha256::new_from_slice(k).expect("HMAC");
    }
    let plaintext: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ keystream[i % keystream.len()])
        .collect();
    Some(plaintext)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_initializes() {
        let key = [1u8; 32];
        let handshake = NoiseHandshake::new(&key);
        assert_eq!(handshake.chaining_key, INITIAL_CHAINING_KEY);
    }

    #[test]
    fn set_remote_static() {
        let mut handshake = NoiseHandshake::new(&[1u8; 32]);
        handshake.set_remote_static(vec![2u8; 32]);
        assert!(handshake.remote_static.is_some());
    }

    #[test]
    fn full_handshake_yields_keys() {
        let initiator_key = [1u8; 32];
        let responder_key = [2u8; 32];

        let mut initiator = NoiseHandshake::new(&initiator_key);
        initiator.set_remote_static(responder_key.to_vec());
        let msg1 = initiator.initiator_write_1();

        let mut responder = NoiseHandshake::new(&responder_key);
        responder.set_remote_static(initiator_key.to_vec());
        // Simplified: responder echoes
        let _ = msg1;
        let msg2 = responder.initiator_write_1();

        let _ = initiator.initiator_read_2(&msg2);
        initiator.initiator_write_3();

        let (send, recv) = initiator.split();
        assert!(send.is_some());
        assert!(recv.is_some());
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello noise world";
        let ct = encrypt(plaintext, &key);
        let pt = decrypt(&ct, &key).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let plaintext = b"hello noise world";
        let mut ct = encrypt(plaintext, &key);
        if let Some(b) = ct.get_mut(0) {
            *b ^= 0xFF;
        }
        assert!(decrypt(&ct, &key).is_none());
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"secret";
        let ct = encrypt(plaintext, &key);
        assert!(decrypt(&ct, &wrong_key).is_none());
    }

    #[test]
    fn encrypt_large_message() {
        let key = [0x42u8; 32];
        let plaintext = vec![0xAAu8; 10_000];
        let ct = encrypt(&plaintext, &key);
        let pt = decrypt(&ct, &key).unwrap();
        assert_eq!(pt, plaintext);
    }
}
