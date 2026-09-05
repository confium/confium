//! Static identities for the Noise_XX handshake.

use sha2::{Digest, Sha256};
use snow::Builder;

/// A Noise static keypair. The private half never leaves the process
/// unless the operator provisions it via `to_hex`/`from_hex`.
#[derive(Clone)]
pub struct NoiseIdentity {
    pub(crate) private: Vec<u8>,
    pub(crate) public: [u8; 32],
}

impl NoiseIdentity {
    /// Generate a fresh static keypair from the OS RNG.
    pub fn generate() -> Self {
        let keypair = Builder::new(noise_params())
            .generate_keypair()
            .expect("snow generates keypairs from the OS RNG");
        let mut public = [0u8; 32];
        public.copy_from_slice(&keypair.public);
        Self {
            private: keypair.private.clone(),
            public,
        }
    }

    /// The 32-byte static public key.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// Hex encoding of the private key, for provisioning a stable
    /// identity through configuration.
    pub fn to_hex(&self) -> String {
        hex(&self.private)
    }

    /// Reconstruct an identity from a hex private key. The public
    /// half is derived with X25519 (snow consumes the private key
    /// directly; it does not derive the public for us).
    pub fn from_hex(hex_private: &str) -> Result<Self, String> {
        let bytes: [u8; 32] = unhex(hex_private)?
            .try_into()
            .map_err(|_| "noise private key must be 32 bytes".to_string())?;
        let secret = x25519_dalek::StaticSecret::from(bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Self {
            private: bytes.to_vec(),
            public: {
                let mut p = [0u8; 32];
                p.copy_from_slice(public.as_bytes());
                p
            },
        })
    }

    /// SHA-256 fingerprint of the static public key — the value a peer
    /// pins via the `pinned=` URL parameter.
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint_of(&self.public)
    }
}

impl std::fmt::Debug for NoiseIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: never render key material.
        f.debug_struct("NoiseIdentity")
            .field("fingerprint", &hex(&fingerprint_of(&self.public)))
            .finish()
    }
}

pub(crate) fn noise_params() -> snow::params::NoiseParams {
    "Noise_XX_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("built-in noise pattern")
}

pub(crate) fn fingerprint_of(public: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"confium-noise-static-v1");
    h.update(public);
    h.finalize().into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_identity() {
        let id = NoiseIdentity::generate();
        let restored = NoiseIdentity::from_hex(&id.to_hex()).unwrap();
        assert_eq!(id.public(), restored.public());
    }

    #[test]
    fn bad_hex_rejected() {
        assert!(NoiseIdentity::from_hex("zz").is_err());
        assert!(NoiseIdentity::from_hex("abc").is_err());
    }
}
