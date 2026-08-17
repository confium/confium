//! Post-quantum signature support: ML-DSA (FIPS 204).
//!
//! Real verification and keypair generation through the RustCrypto
//! `ml-dsa` crate, feature-gated via `pq`. The classical side of the
//! composite signature (Ed25519, ECDSA-P256) remains always-on; with
//! `--features pq` the composite verifier additionally accepts
//! ML-DSA-44/65/87 components, enabling the classical+PQC transition
//! composite (SIGNATIF §9.4: AND-composition, all components must
//! verify).
//!
//! Key sizes (FIPS 204):
//!
//! | Parameter set | Public key | Signature |
//! |---------------|-----------:|----------:|
//! | ML-DSA-44     | 1312 B    | 2420 B    |
//! | ML-DSA-65     | 1952 B    | 3309 B    |
//! | ML-DSA-87     | 2592 B    | 4627 B    |

#[cfg(feature = "pq")]
mod mldsa {
    use ml_dsa::MlDsa65;
    use ml_dsa::Signature as MlDsa65Signature;
    use ml_dsa::SigningKey as MlDsa65SigningKey;
    use ml_dsa::VerifyingKey as MlDsa65VerifyingKey;

    /// Minimum security strength: signatures below ML-DSA-44 are not
    /// accepted (SIGNATIF `minimum-security-parameters`: 128 bits).
    pub const MIN_SECURITY_STRENGTH_BITS: u32 = 128;

    /// Errors from the post-quantum verifier.
    #[derive(Debug, thiserror::Error)]
    pub enum PqError {
        /// The public key bytes are not a valid ML-DSA-65 key.
        #[error("invalid ML-DSA-65 public key: expected 1952 bytes, got {0}")]
        InvalidPublicKey(usize),
        /// The signature bytes are not a valid ML-DSA-65 signature.
        #[error("invalid ML-DSA-65 signature: expected 3309 bytes, got {0}")]
        InvalidSignature(usize),
        /// The signature did not verify.
        #[error("ML-DSA-65 signature verification failed")]
        VerificationFailed,
    }

    /// The ML-DSA-65 public-key size in bytes.
    pub const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
    /// The ML-DSA-65 signature size in bytes.
    pub const MLDSA65_SIGNATURE_LEN: usize = 3309;

    /// Verify an ML-DSA-65 signature.
    ///
    /// `public_key` is the raw ML-DSA-65 public key (1952 bytes),
    /// `message` the signed content, `signature` the raw signature
    /// (3309 bytes).
    ///
    /// # Errors
    ///
    /// Returns a human-readable error for wrong sizes and verification
    /// failures. (The `String` error type predates the placeholder
    /// removal and is kept for 0.4.x semver compatibility; the structured
    /// variant is [`verify_mldsa65_detailed`].)
    pub fn verify_mldsa65(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        verify_mldsa65_detailed(public_key, message, signature).map_err(|e| e.to_string())
    }

    /// Verify an ML-DSA-65 signature with structured errors.
    ///
    /// # Errors
    ///
    /// Size errors for malformed inputs;
    /// [`PqError::VerificationFailed`] when the signature does not verify.
    pub fn verify_mldsa65_detailed(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), PqError> {
        if public_key.len() != MLDSA65_PUBLIC_KEY_LEN {
            return Err(PqError::InvalidPublicKey(public_key.len()));
        }
        if signature.len() != MLDSA65_SIGNATURE_LEN {
            return Err(PqError::InvalidSignature(signature.len()));
        }
        let encoded_vk: ml_dsa::EncodedVerifyingKey<MlDsa65> = public_key
            .try_into()
            .map_err(|_| PqError::InvalidPublicKey(public_key.len()))?;
        let vk = MlDsa65VerifyingKey::<MlDsa65>::decode(&encoded_vk);
        let encoded_sig: ml_dsa::EncodedSignature<MlDsa65> = signature
            .try_into()
            .map_err(|_| PqError::InvalidSignature(signature.len()))?;
        let sig = MlDsa65Signature::<MlDsa65>::decode(&encoded_sig)
            .ok_or(PqError::InvalidSignature(signature.len()))?;
        use ml_dsa::signature::Verifier as _;
        vk.verify(message, &sig)
            .map_err(|_| PqError::VerificationFailed)
    }

    /// An ML-DSA-65 keypair for signing and verification.
    #[derive(Debug, Clone)]
    pub struct MlDsa65Keypair {
        /// The raw public key (1952 bytes).
        pub public_key: Vec<u8>,
        signing: MlDsa65SigningKey<MlDsa65>,
    }

    impl MlDsa65Keypair {
        /// Generate a fresh keypair from the OS RNG.
        ///
        /// # Errors
        ///
        /// Never fails in practice; the error type keeps the API future
        /// proof.
        pub fn generate() -> Self {
            use rand_core::RngCore as _;
            let mut seed = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut seed);
            let signing = MlDsa65SigningKey::<MlDsa65>::from_seed(&seed.into());
            use ml_dsa::signature::Keypair as _;
            let public_key = signing.verifying_key().encode().to_vec();
            Self {
                public_key,
                signing,
            }
        }

        /// Sign a message.
        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            use ml_dsa::signature::Signer as _;
            self.signing.sign(message).encode().to_vec()
        }

        /// Verify a signature produced by this keypair.
        ///
        /// # Errors
        ///
        /// Propagates verification errors.
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), PqError> {
            verify_mldsa65_detailed(&self.public_key, message, signature)
        }
    }

    #[cfg(all(test, feature = "pq"))]
    mod tests {

        use super::*;

        #[test]
        fn generate_sign_verify_round_trip() {
            let kp = MlDsa65Keypair::generate();
            assert_eq!(kp.public_key.len(), MLDSA65_PUBLIC_KEY_LEN);
            let msg = b"confium signatif pq transition";
            let sig = kp.sign(msg);
            assert_eq!(sig.len(), MLDSA65_SIGNATURE_LEN);
            assert!(kp.verify(msg, &sig).is_ok());
            assert!(kp.verify(b"tampered", &sig).is_err());
            let mut bad = sig.clone();
            bad[10] ^= 1;
            assert!(kp.verify(msg, &bad).is_err());
        }

        #[test]
        fn size_errors_are_precise() {
            let err = verify_mldsa65(&[0u8; 10], b"m", &[0u8; 3309]).unwrap_err();
            assert!(err.to_string().contains("public key"));
            let err = verify_mldsa65(&[0u8; 1952], b"m", &[0u8; 10]).unwrap_err();
            assert!(err.to_string().contains("signature"));
        }

        #[test]
        fn minimum_strength_documented() {
            assert_eq!(MIN_SECURITY_STRENGTH_BITS, 128);
        }

        #[test]
        fn transition_composite_and_semantics() {
            use crate::{ComponentSignature, CompositeSignature, MLDSA65, transition_verifier};

            let msg = b"supply-chain provenance record";
            use rand_core::RngCore as _;
            let mut ed_seed = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut ed_seed);
            let ed = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
            use ed25519_dalek::Signer as _;
            let pq_kp = MlDsa65Keypair::generate();

            let composite = CompositeSignature::new(vec![
                ComponentSignature {
                    algorithm: "Ed25519".into(),
                    public_key: ed.verifying_key().as_bytes().to_vec(),
                    signature: ed.sign(msg).to_bytes().to_vec(),
                },
                ComponentSignature {
                    algorithm: MLDSA65.into(),
                    public_key: pq_kp.public_key.clone(),
                    signature: pq_kp.sign(msg),
                },
            ]);
            let ok = composite
                .verify(msg.as_slice(), transition_verifier)
                .unwrap();
            assert!(ok.all_verified, "components: {:?}", ok.per_component);

            // AND semantics: breaking one component breaks the composite.
            let mut broken = composite.clone();
            broken.components[1].signature[100] ^= 1;
            let bad = broken.verify(msg.as_slice(), transition_verifier).unwrap();
            assert!(!bad.all_verified);
        }
    }
}

#[cfg(feature = "pq")]
pub use mldsa::*;
// ============================================================================
// SLH-DSA (FIPS 205) — feature `pq-slh`
// ============================================================================

#[cfg(feature = "pq-slh")]
mod slh {
    use slh_dsa::Sha2_128s;
    use slh_dsa::Signature as SlhSignature;
    use slh_dsa::SigningKey as SlhSigningKey;
    use slh_dsa::VerifyingKey as SlhVerifyingKey;

    /// The SLH-DSA-SHA2-128s public-key size in bytes.
    pub const SLHDSA128S_PUBLIC_KEY_LEN: usize = 32;
    /// The SLH-DSA-SHA2-128s signature size in bytes.
    pub const SLHDSA128S_SIGNATURE_LEN: usize = 7856;

    /// Errors from the SLH-DSA verifier.
    #[derive(Debug, thiserror::Error)]
    pub enum SlhError {
        /// Malformed public key.
        #[error("invalid SLH-DSA-128s public key: expected 32 bytes, got {0}")]
        InvalidPublicKey(usize),
        /// Malformed signature.
        #[error("invalid SLH-DSA-128s signature: expected 7856 bytes, got {0}")]
        InvalidSignature(usize),
        /// The signature did not verify.
        #[error("SLH-DSA-128s signature verification failed")]
        VerificationFailed,
    }

    /// Verify an SLH-DSA-SHA2-128s signature with structured errors.
    ///
    /// # Errors
    ///
    /// Size errors for malformed inputs; verification failure otherwise.
    pub fn verify_slhdsa128s_detailed(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SlhError> {
        if public_key.len() != SLHDSA128S_PUBLIC_KEY_LEN {
            return Err(SlhError::InvalidPublicKey(public_key.len()));
        }
        if signature.len() != SLHDSA128S_SIGNATURE_LEN {
            return Err(SlhError::InvalidSignature(signature.len()));
        }
        let bytes: [u8; SLHDSA128S_PUBLIC_KEY_LEN] = public_key.try_into().expect("32 bytes");
        let vk: SlhVerifyingKey<Sha2_128s> =
            SlhVerifyingKey::from(hybrid_array::Array::from(bytes));
        let sig = SlhSignature::<Sha2_128s>::try_from(signature)
            .map_err(|_| SlhError::InvalidSignature(signature.len()))?;
        use slh_dsa::signature::Verifier as _;
        vk.verify(message, &sig)
            .map_err(|_| SlhError::VerificationFailed)
    }

    /// Verify an SLH-DSA-SHA2-128s signature (`String` errors, matching
    /// the ML-DSA convention for 0.4.x).
    ///
    /// # Errors
    ///
    /// Human-readable errors for malformed inputs and failures.
    pub fn verify_slhdsa128s(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        verify_slhdsa128s_detailed(public_key, message, signature).map_err(|e| e.to_string())
    }

    /// An SLH-DSA-SHA2-128s keypair. Generated from three seed values
    /// (sk_seed, sk_prf, pk_seed), so no RNG-version coupling leaks into
    /// the public API.
    #[derive(Debug, Clone)]
    pub struct SlhDsa128sKeypair {
        /// The raw public key (32 bytes).
        pub public_key: Vec<u8>,
        signing: SlhSigningKey<Sha2_128s>,
    }

    impl SlhDsa128sKeypair {
        /// Generate a fresh keypair from the OS RNG.
        pub fn generate() -> Self {
            use rand_core::RngCore as _;
            let mut sk_seed = [0u8; 16];
            let mut sk_prf = [0u8; 16];
            let mut pk_seed = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut sk_seed);
            rand_core::OsRng.fill_bytes(&mut sk_prf);
            rand_core::OsRng.fill_bytes(&mut pk_seed);
            let signing =
                SlhSigningKey::<Sha2_128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
            use slh_dsa::signature::Keypair as _;
            let public_key = signing.verifying_key().to_vec();
            Self {
                public_key,
                signing,
            }
        }

        /// Sign a message (deterministic).
        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            use slh_dsa::signature::Signer as _;
            self.signing.sign(message).to_vec()
        }

        /// Verify a signature produced by this keypair.
        ///
        /// # Errors
        ///
        /// Propagates verification errors.
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SlhError> {
            verify_slhdsa128s_detailed(&self.public_key, message, signature)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trip_and_tamper() {
            let kp = SlhDsa128sKeypair::generate();
            assert_eq!(kp.public_key.len(), SLHDSA128S_PUBLIC_KEY_LEN);
            let msg = b"post-quantum stateless hash-based";
            let sig = kp.sign(msg);
            assert_eq!(sig.len(), SLHDSA128S_SIGNATURE_LEN);
            assert!(kp.verify(msg, &sig).is_ok());
            assert!(kp.verify(b"other", &sig).is_err());
            let mut bad = sig.clone();
            bad[100] ^= 1;
            assert!(kp.verify(msg, &bad).is_err());
        }

        #[test]
        fn size_errors() {
            assert!(verify_slhdsa128s(&[0u8; 31], b"m", &[0u8; 7856]).is_err());
            assert!(verify_slhdsa128s(&[0u8; 32], b"m", &[0u8; 10]).is_err());
        }
    }
}

#[cfg(feature = "pq-slh")]
pub use slh::*;
