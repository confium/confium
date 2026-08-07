//! In-process synchronous driver for FROST-ed25519 DKG and signing.
//!
//! Thin wrapper over [`confium_tc::inprocess`] that names the
//! FROST-ed25519 schemes and pulls the joint public key out of the
//! first share. Completes the threshold-ECDSA / threshold-EdDSA
//! matrix — CMP20 and GG18 cover P-256; this covers Ed25519.

use confium_tc::Result;
use confium_tc::inprocess as driver;

/// Outcome of a FROST-ed25519 DKG.
#[derive(Debug, Clone)]
pub struct KeygenOutput {
    /// Per-party share blobs.
    pub shares: Vec<Vec<u8>>,
    /// Joint Ed25519 public key (32 bytes).
    pub public_key: Vec<u8>,
}

/// Run FROST-ed25519 DKG for `party_count` parties at threshold
/// `threshold`.
pub fn keygen(threshold: u32, party_count: usize) -> Result<Vec<Vec<u8>>> {
    driver::run_dkg(crate::DKG_SCHEME, threshold, party_count)
}

/// Threshold-sign `message` with FROST-ed25519. Returns a 64-byte
/// Ed25519 signature.
pub fn sign(share_blobs: &[Vec<u8>], threshold: u32, message: &[u8]) -> Result<Vec<u8>> {
    driver::run_sign(crate::SIGN_SCHEME, share_blobs, threshold, message)
}

/// Sign N messages against the same joint key.
pub fn sign_batch(
    share_blobs: &[Vec<u8>],
    threshold: u32,
    messages: &[&[u8]],
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(messages.len());
    for msg in messages {
        out.push(sign(share_blobs, threshold, msg)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkg_and_sign_round_trip() {
        let shares = keygen(2, 3).expect("dkg");
        assert_eq!(shares.len(), 3);
        let sig = sign(&shares[..2], 2, b"hello ed25519").expect("sign");
        assert!(!sig.is_empty());
    }

    #[test]
    fn below_threshold_errors() {
        let shares = keygen(3, 5).expect("dkg");
        assert!(sign(&shares[..2], 3, b"msg").is_err());
    }
}
