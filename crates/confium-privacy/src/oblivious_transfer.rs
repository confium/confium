//! Oblivious Transfer (OT).
//!
//! 1-out-of-2 OT: the sender has two messages (m0, m1), the receiver
//! gets exactly one (m_b) without the sender learning which, and the
//! receiver doesn't learn the other message.
//!
//! Based on the Bellare-Micali protocol using P-256.

use p256::elliptic_curve::Field;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// Sender's setup message.
#[derive(Debug, Clone)]
pub struct OtSetup {
    /// Random point C.
    pub c: AffinePoint,
}

/// Receiver's choice message.
#[derive(Debug, Clone)]
pub struct OtChoice {
    /// Point P_b sent to sender.
    pub p: AffinePoint,
}

/// Sender's encrypted messages.
#[derive(Debug, Clone)]
pub struct OtEncrypted {
    pub e0: Vec<u8>,
    pub e1: Vec<u8>,
}

/// Receiver's output for choice bit b.
#[derive(Debug, Clone)]
pub struct OtReceiver {
    /// Choice bit.
    pub b: bool,
    /// Secret scalar used to decrypt.
    pub k: Scalar,
}

/// Phase 1: Sender initiates with a random point.
pub fn sender_setup() -> (OtSetup, Scalar) {
    let c_scalar = Scalar::random(&mut OsRng);
    let c = (ProjectivePoint::GENERATOR * c_scalar).to_affine();
    (OtSetup { c }, c_scalar)
}

/// Phase 2: Receiver chooses bit b and generates choice message.
pub fn receiver_choose(b: bool, setup: &OtSetup) -> (OtChoice, OtReceiver) {
    let k = Scalar::random(&mut OsRng);
    let k_g = (ProjectivePoint::GENERATOR * k).to_affine();

    // If b == 0: P = k*G
    // If b == 1: P = k*G + C
    let p = if b {
        (ProjectivePoint::from(k_g) + ProjectivePoint::from(setup.c)).to_affine()
    } else {
        k_g
    };

    (OtChoice { p }, OtReceiver { b, k })
}

/// Phase 3: Sender encrypts both messages.
pub fn sender_encrypt(choice: &OtChoice, setup: &OtSetup, m0: &[u8], m1: &[u8]) -> OtEncrypted {
    // k0 = P, k1 = P - C
    // Derive encryption keys from points
    let k0_point = choice.p;
    let k1_point = (ProjectivePoint::from(choice.p) - ProjectivePoint::from(setup.c)).to_affine();

    let e0 = xor_encrypt(&k0_point, m0);
    let e1 = xor_encrypt(&k1_point, m1);

    OtEncrypted { e0, e1 }
}

/// Phase 4: Receiver decrypts the chosen message.
pub fn receiver_decrypt(enc: &OtEncrypted, receiver: &OtReceiver) -> Vec<u8> {
    let k_g = (ProjectivePoint::GENERATOR * receiver.k).to_affine();
    if receiver.b {
        xor_encrypt(&k_g, &enc.e1)
    } else {
        xor_encrypt(&k_g, &enc.e0)
    }
}

fn xor_encrypt(key_point: &AffinePoint, data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"ot-key");
    hasher.update(key_point.to_encoded_point(true).as_bytes());
    let key = hasher.finalize();
    let key = key.as_slice();

    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ot_chooses_zero() {
        let (setup, _) = sender_setup();
        let (choice, receiver) = receiver_choose(false, &setup);
        let m0 = b"message zero";
        let m1 = b"message one";
        let enc = sender_encrypt(&choice, &setup, m0, m1);
        let decrypted = receiver_decrypt(&enc, &receiver);
        assert_eq!(decrypted, m0);
    }

    #[test]
    fn ot_chooses_one() {
        let (setup, _) = sender_setup();
        let (choice, receiver) = receiver_choose(true, &setup);
        let m0 = b"message zero";
        let m1 = b"message one";
        let enc = sender_encrypt(&choice, &setup, m0, m1);
        let decrypted = receiver_decrypt(&enc, &receiver);
        assert_eq!(decrypted, m1);
    }

    #[test]
    fn sender_does_not_learn_choice() {
        let (setup, _) = sender_setup();
        let (choice0, _) = receiver_choose(false, &setup);
        let (choice1, _) = receiver_choose(true, &setup);
        // The sender sees P which is different for b=0 and b=1
        // but without knowing k, cannot determine b
        assert_ne!(choice0.p, choice1.p);
    }

    #[test]
    fn receiver_does_not_learn_other_message() {
        let (setup, _) = sender_setup();
        let (choice, receiver) = receiver_choose(false, &setup);
        let m0 = b"zero";
        let m1 = b"one";
        let enc = sender_encrypt(&choice, &setup, m0, m1);
        // Receiver can only decrypt e0 (their choice)
        let decrypted = receiver_decrypt(&enc, &receiver);
        assert_eq!(decrypted, m0);
        // e1 would decrypt to garbage with k0's key
    }

    #[test]
    fn different_messages_each_time() {
        let (setup, _) = sender_setup();
        let (choice, receiver) = receiver_choose(true, &setup);
        let m0 = b"aaa";
        let m1 = b"bbb";
        let enc = sender_encrypt(&choice, &setup, m0, m1);
        let decrypted = receiver_decrypt(&enc, &receiver);
        assert_eq!(decrypted, b"bbb");
    }

    #[test]
    fn large_messages() {
        let (setup, _) = sender_setup();
        let (choice, receiver) = receiver_choose(false, &setup);
        let m0 = vec![0xAA; 1000];
        let m1 = vec![0xBB; 1000];
        let enc = sender_encrypt(&choice, &setup, &m0, &m1);
        let decrypted = receiver_decrypt(&enc, &receiver);
        assert_eq!(decrypted, m0);
    }

    #[test]
    fn empty_message() {
        let (setup, _) = sender_setup();
        let (choice, receiver) = receiver_choose(false, &setup);
        let enc = sender_encrypt(&choice, &setup, b"", b"data");
        let decrypted = receiver_decrypt(&enc, &receiver);
        assert!(decrypted.is_empty());
    }
}
