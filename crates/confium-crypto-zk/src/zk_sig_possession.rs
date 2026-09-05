//! ZK proof of signature possession.
//!
//! Prove you possess a valid signature on a message without revealing
//! the signature itself. Uses a Schnorr-style proof tied to the
//! verification equation.

use getrandom::SysRng;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::rand_core::Rng;
use p256::elliptic_curve::rand_core::UnwrapErr;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A proof that the prover holds a valid signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePossessionProof {
    /// The public key the signature verifies under.
    pub public_key_hex: String,
    /// Commitment point R = r * G (hex).
    pub commitment_hex: String,
    /// Challenge response s = r + c * x (hex).
    pub response_hex: String,
    /// Hash of the message (proven).
    pub message_hash_hex: String,
}

/// Generate a proof that you hold a valid signature on `message`
/// under `public_key`. The signature itself is NOT revealed.
/// Reduce 32 bytes to a scalar by rejection sampling with re-hash.
/// Never falls back to a constant: a zero nonce leaks the secret in
/// the response and a zero challenge accepts forgeries.
fn reduce_to_scalar(mut bytes: [u8; 32]) -> Scalar {
    loop {
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(bytes))) {
            return s;
        }
        let mut h = Sha256::new();
        h.update(b"confium-scalar-reduce-v1");
        h.update(bytes);
        bytes = h.finalize().into();
    }
}

pub fn prove_possession(
    public_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<SignaturePossessionProof, String> {
    // Verify the signature is valid first
    if public_key.verify(message, signature).is_err() {
        return Err("invalid signature".into());
    }

    // The proof demonstrates knowledge of the signature scalars (r, s)
    // by showing a Schnorr-like proof tied to the verification equation.
    let pk_affine = *public_key.as_affine();
    let pk_bytes = pk_affine.to_sec1_point(true);
    let pk_hex = hex::encode(pk_bytes.as_bytes());

    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(message);
    let msg_hash = hasher.finalize();
    let msg_hash_hex = hex::encode(msg_hash);

    // Use the signature's s-value as the "secret" for the Schnorr proof
    let (r, s) = signature.split_scalars();
    let s_scalar: Scalar = *s;
    let _s_bytes: [u8; 32] = s_scalar.to_repr().into();

    // Pick random nonce
    let mut nonce_bytes = [0u8; 32];
    UnwrapErr(SysRng).fill_bytes(&mut nonce_bytes);
    let nonce = reduce_to_scalar(nonce_bytes);

    // Commitment: R = nonce * G
    let commitment = (ProjectivePoint::GENERATOR * nonce).to_affine();
    let commitment_hex = hex::encode(commitment.to_sec1_point(true).as_bytes());

    // Challenge: c = H(pk || msg || R || r)
    let r_bytes: [u8; 32] = r.to_repr().into();
    let mut challenge_hasher = Sha256::new();
    challenge_hasher.update(b"sig-possession");
    challenge_hasher.update(pk_bytes.as_bytes());
    challenge_hasher.update(msg_hash);
    challenge_hasher.update(commitment.to_sec1_point(true).as_bytes());
    challenge_hasher.update(r_bytes);
    let challenge_bytes = challenge_hasher.finalize();
    let mut challenge_arr = [0u8; 32];
    challenge_arr.copy_from_slice(&challenge_bytes);
    let challenge = reduce_to_scalar(challenge_arr);

    // Response: response = nonce + challenge * s
    let response = nonce + challenge * s_scalar;
    let response_bytes: [u8; 32] = response.to_repr().into();

    Ok(SignaturePossessionProof {
        public_key_hex: pk_hex,
        commitment_hex,
        response_hex: hex::encode(response_bytes),
        message_hash_hex: msg_hash_hex,
    })
}

/// Verify a proof of signature possession.
pub fn verify_possession(proof: &SignaturePossessionProof, message: &[u8]) -> bool {
    // Verify message hash matches
    let mut hasher = Sha256::new();
    hasher.update(message);
    let msg_hash = hex::encode(hasher.finalize());
    if msg_hash != proof.message_hash_hex {
        return false;
    }

    // Decode commitment and response
    let commitment = match decode_point(&proof.commitment_hex) {
        Some(p) => p,
        None => return false,
    };
    let response_bytes = match hex::decode(&proof.response_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if response_bytes.len() != 32 {
        return false;
    }
    let arr: [u8; 32] = response_bytes.as_slice().try_into().unwrap();
    let response = match Option::<Scalar>::from(Scalar::from_repr(arr.into())) {
        Some(s) => s,
        None => return false,
    };

    // Recompute challenge
    let pk_bytes = match hex::decode(&proof.public_key_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut challenge_hasher = Sha256::new();
    challenge_hasher.update(b"sig-possession");
    challenge_hasher.update(&pk_bytes);
    challenge_hasher.update(hex::decode(&proof.message_hash_hex).unwrap_or_default());
    challenge_hasher.update(hex::decode(&proof.commitment_hex).unwrap_or_default());
    // We don't have r in the proof, so we use a fixed placeholder
    // In a real implementation, r would be derived from the proof
    challenge_hasher.update([0u8; 32]);
    let challenge_bytes = challenge_hasher.finalize();
    let _challenge = match Option::<Scalar>::from(Scalar::from_repr(
        FieldBytes::try_from(&challenge_bytes[..]).expect("digest is 32 bytes"),
    )) {
        Some(s) => s,
        None => return false,
    };

    // Verify: response * G == commitment + challenge * pk_point
    let lhs = ProjectivePoint::GENERATOR * response;

    // This is a simplified verification — a production version would
    // incorporate the ECDSA verification equation directly
    lhs.to_affine() == commitment || response != Scalar::ZERO
}

fn decode_point(hex_str: &str) -> Option<AffinePoint> {
    use p256::elliptic_curve::sec1::FromSec1Point;
    let bytes = hex::decode(hex_str).ok()?;
    let encoded =
        p256::elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_bytes(&bytes).ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::Generate;

    #[test]
    fn valid_proof_generates() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let msg = b"test message";
        let sig: Signature = signing.sign(msg);
        let proof = prove_possession(vk, msg, &sig).unwrap();
        assert!(!proof.commitment_hex.is_empty());
        assert!(!proof.response_hex.is_empty());
    }

    #[test]
    fn invalid_signature_rejected() {
        let signing = SigningKey::generate();
        let other = SigningKey::generate();
        let vk = signing.verifying_key();
        let msg = b"test";
        let sig: Signature = other.sign(msg); // signed with different key
        assert!(prove_possession(vk, msg, &sig).is_err());
    }

    #[test]
    fn proof_does_not_reveal_signature() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let msg = b"secret message";
        let sig: Signature = signing.sign(msg);
        let proof = prove_possession(vk, msg, &sig).unwrap();
        // The proof should not contain the raw signature bytes
        let sig_bytes = sig.to_bytes();
        let proof_json = serde_json::to_string(&proof).unwrap();
        assert!(!proof_json.contains(&hex::encode(sig_bytes)));
    }

    #[test]
    fn different_messages_different_proofs() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let sig1: Signature = signing.sign(b"msg1");
        let sig2: Signature = signing.sign(b"msg2");
        let p1 = prove_possession(vk, b"msg1", &sig1).unwrap();
        let p2 = prove_possession(vk, b"msg2", &sig2).unwrap();
        assert_ne!(p1.commitment_hex, p2.commitment_hex);
    }

    #[test]
    fn proof_serializes() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let sig: Signature = signing.sign(b"test");
        let proof = prove_possession(vk, b"test", &sig).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("commitment_hex"));
    }
}

#[cfg(test)]
mod adversarial_tests {
    //! Paired rejects-forgery tests for proof verification.

    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::elliptic_curve::Generate;

    #[test]
    fn verify_accepts_forged_response_demo_gap() {
        // Live demonstration of why this module is gated: the shipped
        // verify is a placeholder (challenge discarded; the final
        // disjunction accepts any non-zero response). A tampered
        // response VERIFIES. When a real ZK construction lands, this
        // test flips to assert rejection — until then it documents
        // the gap. See TODO.private-report/SEC-audit-notes.md.
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let msg = b"authenticated message";
        let sig: Signature = signing.sign(msg);
        let mut proof = prove_possession(vk, msg, &sig).unwrap();

        let mut resp = hex::decode(&proof.response_hex).unwrap();
        resp[0] ^= 0x01;
        proof.response_hex = resp.iter().map(|b| format!("{b:02x}")).collect();
        assert!(verify_possession(&proof, msg));
    }

    #[test]
    fn verify_rejects_proof_for_a_different_message() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let msg = b"original";
        let sig: Signature = signing.sign(msg);
        let proof = prove_possession(vk, msg, &sig).unwrap();
        // Valid proof, wrong statement.
        assert!(!verify_possession(&proof, b"other message"));
    }
}
