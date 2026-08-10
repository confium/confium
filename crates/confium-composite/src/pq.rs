//! Post-quantum signature verification (ML-DSA / SLH-DSA).
//!
//! Feature-gated via the `pq` Cargo feature. When enabled, the
//! composite signature verifier can verify ML-DSA-65 components
//! alongside classical algorithms (Ed25519, ECDSA-P256).
//!
//! ## Current status
//!
//! This module provides the verification dispatch shape. The actual
//! ML-DSA verification uses the `p256` crate for the classical side
//! and a placeholder for the PQ side. When a mature Rust ML-DSA crate
//! (e.g., `fips204`, `pqcrypto-dilithium`) is available as a workspace
//! dependency, the `verify_mldsa65` function wraps it.
//!
//! ## Usage
//!
//! ```ignore
//! use confium_composite::pq::verify_mldsa65;
//!
//! let ok = verify_mldsa65(public_key, message, signature)?;
//! ```

/// Verify an ML-DSA-65 signature.
///
/// `public_key` is the raw ML-DSA-65 public key bytes.
/// `message` is the signed message.
/// `signature` is the raw ML-DSA-65 signature bytes.
///
/// Returns `Ok(())` if the signature is valid, `Err` otherwise.
pub fn verify_mldsa65(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    // ML-DSA-65 signature sizes (FIPS 204):
    //   signature: 3309 bytes
    //   public key: 1952 bytes
    if signature.len() > 4000 {
        return Err(format!(
            "ML-DSA-65 signature too large: {} bytes (expected ≤3309)",
            signature.len()
        ));
    }
    if public_key.len() > 2048 {
        return Err(format!(
            "ML-DSA-65 public key too large: {} bytes (expected ≤1952)",
            public_key.len()
        ));
    }

    // Placeholder: when a Rust ML-DSA crate is added as a dependency,
    // this function calls its verifier. For now, reject all signatures
    // with a clear error so callers know PQ verification is not yet
    // wired to a real implementation.
    let _ = message;
    Err(
        "ML-DSA-65 verification not yet wired to a real implementation. \
         Add `fips204` or `pqcrypto-dilithium` as a dependency and \
         implement the verifier call here."
            .to_string(),
    )
}

/// Verify a SLH-DSA-SHA2-192s signature (FIPS 205).
pub fn verify_slh_dsa(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let _ = (public_key, message, signature);
    Err(
        "SLH-DSA verification not yet wired to a real implementation. \
         Add a SLH-DSA Rust crate as a dependency."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa65_rejects_too_large_signature() {
        let big_sig = vec![0u8; 5000];
        let result = verify_mldsa65(&[0u8; 1952], b"msg", &big_sig);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }

    #[test]
    fn mldsa65_rejects_too_large_public_key() {
        let big_pk = vec![0u8; 3000];
        let result = verify_mldsa65(&big_pk, b"msg", &[0u8; 3309]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }

    #[test]
    fn mldsa65_placeholder_returns_clear_error() {
        let result = verify_mldsa65(&[0u8; 100], b"msg", &[0u8; 100]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet wired"));
    }
}
