//! Schnorr proof of possession of a P-256 signing key.
//!
//! Proves knowledge of the discrete logarithm `x` of a public key
//! `X = x·G`, bound to an arbitrary context string through the
//! Fiat-Shamir challenge. This is the standard rogue-key defense:
//! key-aggregation schemes (MuSig-style multi-signatures, threshold
//! enrollment) must require each contributor to prove possession of
//! the key it submits — otherwise a malicious contributor crafts a
//! share such that the aggregate key is one it controls alone.
//!
//! The construction is a textbook Schnorr identification protocol
//! made non-interactive with Fiat-Shamir. The statement (public key
//! AND context) is bound into the challenge, so a proof does not
//! transfer to another key or another context.
//!
//! For proving possession of an ECDSA *signature* without revealing
//! it, see `zk_sig_possession` — that statement contains the
//! coordinate check `x(R) ≡ r (mod n)`, which is a bit-decomposition
//! relation no plain sigma-protocol can carry; it stays gated until a
//! circuit-based construction lands.

use getrandom::SysRng;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::rand_core::Rng;
use p256::elliptic_curve::rand_core::UnwrapErr;
use p256::elliptic_curve::sec1::FromSec1Point;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A proof that the prover knows the signing key behind a public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPossessionProof {
    /// The public key this proof attests to (hex, SEC1 compressed).
    pub public_key_hex: String,
    /// Commitment point `R = r·G` (hex, SEC1 compressed).
    pub commitment_hex: String,
    /// Response `z = r + c·x` (hex).
    pub response_hex: String,
    /// SHA-256 of the bound context (hex) — proofs do not transfer
    /// across contexts.
    pub context_hex: String,
}

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

fn hash_context(context: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"confium-key-possession-context-v1");
    hasher.update(context);
    hasher.finalize().into()
}

fn challenge(public_key: &[u8], context_hash: &[u8; 32], commitment: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"confium-key-possession-v1");
    hasher.update(public_key);
    hasher.update(context_hash);
    hasher.update(commitment);
    let mut bytes: [u8; 32] = hasher.finalize().into();
    reduce_to_scalar(bytes)
}

/// Prove possession of the signing key behind `signing_key`, bound to
/// `context`. The signing key itself never leaves the prover.
pub fn prove_key_possession(
    signing_key: &SigningKey,
    context: &[u8],
) -> Result<KeyPossessionProof, String> {
    let verifying = signing_key.verifying_key();
    let pk_bytes = verifying.as_affine().to_sec1_point(true);
    let pk_hex = hex::encode(pk_bytes.as_bytes());
    let context_hash = hash_context(context);
    let context_hex = hex::encode(context_hash);

    // to_bytes returns the raw scalar — always canonical, no
    // reduction path to get wrong.
    let x = Option::<Scalar>::from(Scalar::from_repr(signing_key.to_bytes().into()))
        .expect("signing key encodes a canonical scalar");

    loop {
        let mut nonce_bytes = [0u8; 32];
        UnwrapErr(SysRng).fill_bytes(&mut nonce_bytes);
        let nonce = reduce_to_scalar(nonce_bytes);
        if nonce == Scalar::ZERO {
            continue;
        }

        let commitment = (ProjectivePoint::GENERATOR * nonce).to_affine();
        let commitment_bytes = commitment.to_sec1_point(true);
        let c = challenge(
            pk_bytes.as_bytes(),
            &context_hash,
            commitment_bytes.as_bytes(),
        );

        let response = nonce + c * x;
        let response_bytes: [u8; 32] = response.to_repr().into();

        return Ok(KeyPossessionProof {
            public_key_hex: pk_hex,
            commitment_hex: hex::encode(commitment_bytes.as_bytes()),
            response_hex: hex::encode(response_bytes),
            context_hex,
        });
    }
}

/// Verify a key-possession proof for `public_key` and `context`.
pub fn verify_key_possession(
    proof: &KeyPossessionProof,
    context: &[u8],
    public_key: &VerifyingKey,
) -> bool {
    let context_hash = hash_context(context);
    if hex::encode(context_hash) != proof.context_hex {
        return false;
    }

    let pk_bytes = public_key.as_affine().to_sec1_point(true);
    if hex::encode(pk_bytes.as_bytes()) != proof.public_key_hex {
        return false;
    }

    let commitment_bytes = match hex::decode(&proof.commitment_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let encoded = match p256::elliptic_curve::sec1::Sec1Point::<p256::NistP256>::from_bytes(
        &commitment_bytes,
    ) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let commitment = match Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&encoded)) {
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
    let arr: [u8; 32] = match response_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let response = match Option::<Scalar>::from(Scalar::from_repr(arr.into())) {
        Some(s) => s,
        None => return false,
    };
    if response == Scalar::ZERO {
        return false;
    }

    let c = challenge(pk_bytes.as_bytes(), &context_hash, &commitment_bytes);
    let pk_point = ProjectivePoint::from(*public_key.as_affine());

    // z·G == R + c·X
    let lhs = ProjectivePoint::GENERATOR * response;
    let rhs = ProjectivePoint::from(commitment) + pk_point * c;
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Generate;

    #[test]
    fn honest_proof_round_trips() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let proof = prove_key_possession(&signing, b"enroll signer 7").unwrap();
        assert!(verify_key_possession(&proof, b"enroll signer 7", &vk));
    }

    #[test]
    fn proofs_differ_across_contexts() {
        let signing = SigningKey::generate();
        let p1 = prove_key_possession(&signing, b"context-a").unwrap();
        let p2 = prove_key_possession(&signing, b"context-b").unwrap();
        assert_ne!(p1.commitment_hex, p2.commitment_hex);
        assert_ne!(p1.context_hex, p2.context_hex);
    }

    #[test]
    fn proof_does_not_reveal_the_signing_key() {
        let signing = SigningKey::generate();
        let proof = prove_key_possession(&signing, b"context").unwrap();
        let key_bytes = signing.to_bytes();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(!json.contains(&hex::encode(key_bytes)));
    }
}

#[cfg(test)]
mod adversarial_tests {
    //! Paired rejects-forgery tests for proof verification.

    use super::*;
    use p256::elliptic_curve::Generate;

    #[test]
    fn verify_rejects_tampered_response() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let mut proof = prove_key_possession(&signing, b"ctx").unwrap();

        let mut resp = hex::decode(&proof.response_hex).unwrap();
        resp[0] ^= 0x01;
        proof.response_hex = resp.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!verify_key_possession(&proof, b"ctx", &vk));
    }

    #[test]
    fn verify_rejects_tampered_commitment() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let mut proof = prove_key_possession(&signing, b"ctx").unwrap();

        // Swap the commitment for a different valid point: the
        // challenge is bound to the original, so the response cannot
        // satisfy the equation under the new commitment.
        let other_key = SigningKey::generate();
        let other = other_key.verifying_key();
        proof.commitment_hex = hex::encode(other.as_affine().to_sec1_point(true).as_bytes());
        assert!(!verify_key_possession(&proof, b"ctx", &vk));
    }

    #[test]
    fn verify_rejects_proof_for_a_different_context() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let proof = prove_key_possession(&signing, b"original").unwrap();
        // Valid proof, wrong statement.
        assert!(!verify_key_possession(&proof, b"other", &vk));
    }

    #[test]
    fn verify_rejects_proof_under_a_different_key() {
        let signing = SigningKey::generate();
        let other = SigningKey::generate();
        let proof = prove_key_possession(&signing, b"ctx").unwrap();
        assert!(!verify_key_possession(
            &proof,
            b"ctx",
            other.verifying_key()
        ));
    }

    #[test]
    fn verify_rejects_zero_response() {
        let signing = SigningKey::generate();
        let vk = signing.verifying_key();
        let mut proof = prove_key_possession(&signing, b"ctx").unwrap();
        proof.response_hex = hex::encode([0u8; 32]);
        assert!(!verify_key_possession(&proof, b"ctx", &vk));
    }
}
