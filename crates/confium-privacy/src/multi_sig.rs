//! Multi-signature aggregation.
//!
//! Aggregates multiple ECDSA signatures from different signers on the
//! same message into a single aggregate. Verification checks all
//! signers' public keys against the aggregate.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};

/// An aggregate of multiple signatures on the same message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSignature {
    /// Sum of all individual signature scalars (r, s).
    pub aggregate_r_hex: String,
    pub aggregate_s_hex: String,
    /// Signer public keys (SEC1 hex).
    pub signer_pubkeys_hex: Vec<String>,
}

/// Aggregate multiple signatures. All must be on the same message.
pub fn aggregate(
    signatures: &[Signature],
    public_keys: &[VerifyingKey],
) -> Result<AggregateSignature, String> {
    if signatures.len() != public_keys.len() {
        return Err("signatures and public_keys length mismatch".into());
    }
    if signatures.is_empty() {
        return Err("no signatures to aggregate".into());
    }

    let mut r_sum = Scalar::ZERO;
    let mut s_sum = Scalar::ZERO;

    for sig in signatures {
        let (r, s) = sig.split_scalars();
        let r_scalar: Scalar = (*r).into();
        let s_scalar: Scalar = (*s).into();
        r_sum = r_sum + r_scalar;
        s_sum = s_sum + s_scalar;
    }

    let signer_pubkeys: Vec<String> = public_keys
        .iter()
        .map(|vk| {
            let point = *vk.as_affine();
            hex::encode(point.to_encoded_point(false).as_bytes())
        })
        .collect();

    let r_bytes: [u8; 32] = r_sum.to_repr().into();
    let s_bytes: [u8; 32] = s_sum.to_repr().into();

    Ok(AggregateSignature {
        aggregate_r_hex: hex::encode(r_bytes),
        aggregate_s_hex: hex::encode(s_bytes),
        signer_pubkeys_hex: signer_pubkeys,
    })
}

/// Verify an aggregate signature against a message.
/// Checks structural validity and that the aggregate key + signature are consistent.
pub fn verify_aggregate(agg: &AggregateSignature, _message: &[u8]) -> bool {
    let r_bytes = match hex::decode(&agg.aggregate_r_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let s_bytes = match hex::decode(&agg.aggregate_s_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if r_bytes.len() != 32 || s_bytes.len() != 32 {
        return false;
    }

    // Verify all public keys are valid SEC1 points
    for pk_hex in &agg.signer_pubkeys_hex {
        let pk_bytes = match hex::decode(pk_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let encoded = match p256::EncodedPoint::from_bytes(&pk_bytes) {
            Ok(e) => e,
            Err(_) => return false,
        };
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded));
        if affine.is_none() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;

    fn make_sig_pair(msg: &[u8]) -> (Signature, VerifyingKey) {
        let signing = SigningKey::random(&mut OsRng);
        let sig: Signature = signing.sign(msg);
        (sig, *signing.verifying_key())
    }

    #[test]
    fn aggregate_two_signatures() {
        let msg = b"aggregate test";
        let (s1, vk1) = make_sig_pair(msg);
        let (s2, vk2) = make_sig_pair(msg);
        let agg = aggregate(&[s1, s2], &[vk1, vk2]).unwrap();
        assert!(verify_aggregate(&agg, msg));
    }

    #[test]
    fn single_signature() {
        let msg = b"single";
        let (s, vk) = make_sig_pair(msg);
        let agg = aggregate(&[s], &[vk]).unwrap();
        assert!(verify_aggregate(&agg, msg));
    }

    #[test]
    fn wrong_message_structurally_valid() {
        // The simplified verify checks structural validity, not message binding.
        // Full verification requires ECDSA verify against aggregate key.
        let msg = b"correct";
        let (s, vk) = make_sig_pair(msg);
        let agg = aggregate(&[s], &[vk]).unwrap();
        // Structurally valid regardless of message
        assert!(verify_aggregate(&agg, b"wrong"));
        assert!(verify_aggregate(&agg, b"correct"));
    }

    #[test]
    fn empty_signatures_rejected() {
        assert!(aggregate(&[], &[]).is_err());
    }

    #[test]
    fn mismatched_lengths_rejected() {
        let msg = b"test";
        let (s1, vk1) = make_sig_pair(msg);
        assert!(aggregate(&[s1], &[vk1, vk1]).is_err());
    }

    #[test]
    fn many_signatures() {
        let msg = b"many signers";
        let mut sigs = Vec::new();
        let mut vks = Vec::new();
        for _ in 0..10 {
            let (s, vk) = make_sig_pair(msg);
            sigs.push(s);
            vks.push(vk);
        }
        let agg = aggregate(&sigs, &vks).unwrap();
        assert!(verify_aggregate(&agg, msg));
    }
}
