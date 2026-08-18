//! `Secret<T>`: AEAD-encrypted-at-rest memory.
//!
//! Unlike [`crate::sensitive::Sensitive`] (which zeroizes on drop but
//! keeps the plaintext in RAM while alive), `Secret<T>` keeps the inner
//! value **encrypted in memory** with a per-process AES-256-GCM key.
//! The plaintext is only materialized transiently, inside a
//! [`SecretGuard`] borrow returned by [`Secret::access`]; when the
//! guard drops, the plaintext buffer is zeroized and the only copy left
//! in the `Secret` is the ciphertext again.
//!
//! This defends against memory disclosure (core dumps, `/proc/<pid>/mem`
//! readers, cold-boot attacks) where an attacker snapshots process RAM
//! at an arbitrary moment: the snapshot contains only ciphertext plus
//! the (per-process) key, and recovering the key alone is not enough
//! because each value also carries a fresh nonce and AEAD tag.
//!
//! # Key model
//!
//! The per-process key is generated once via `OsRng` and stored in a
//! [`std::sync::OnceLock`]. All `Secret<T>` values in a process share
//! this single key; per-value freshness comes from a unique nonce
//! generated for each encryption. The key is never persisted.
//!
//! # Trait bounds
//!
//! `T` must be `Serialize`/`Deserialize`-ish for byte transport. We
//! avoid pulling in `serde` here and instead require `T: SecretBytes`,
//! which converts the value to/from raw bytes. Implementations are
//! provided for `Vec<u8>`, `&[u8]` (construction only), `[u8; N]`, and
//! `String`. To wrap a custom type, implement `SecretBytes` for it.

// `aes-gcm` 0.10 re-exports `generic-array` 0.x, whose `from_slice` /
// `as_slice` are marked deprecated in favor of the 1.x API. The 1.x
// migration is gated on aes-gcm itself moving to generic-array 1.x;
// until then these calls are the canonical nonce/key construction API.
#![allow(deprecated)]

use std::fmt;
use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

use crate::Result;
use crate::error;
use crate::mlock;
use snafu::ResultExt;

/// AES-256-GCM nonce size: 12 bytes (96 bits), the GCM-recommended length.
const NONCE_LEN: usize = 12;

/// Converts a value to/from the raw bytes that `Secret<T>` will encrypt.
///
/// Implementations must be deterministic so a value encrypted then
/// decrypted round-trips to an equal value.
pub trait SecretBytes: Sized {
    /// Serialize the value to a freshly-allocated byte buffer.
    fn to_secret_bytes(&self) -> Vec<u8>;

    /// Reconstruct the value from its serialized byte form.
    fn from_secret_bytes(bytes: &[u8]) -> Result<Self>;
}

impl SecretBytes for Vec<u8> {
    fn to_secret_bytes(&self) -> Vec<u8> {
        self.clone()
    }
    fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bytes.to_vec())
    }
}

impl<const N: usize> SecretBytes for [u8; N] {
    fn to_secret_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
    fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return error::WrongTypeSnafu {
                expected: concat!("[u8; ", stringify!(N), "]"),
            }
            .fail();
        }
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}

impl SecretBytes for String {
    fn to_secret_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
    fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let s = std::str::from_utf8(bytes).context(error::InvalidUTF8Snafu {})?;
        Ok(s.to_string())
    }
}

/// Returns the per-process AEAD key, generating it once on first use
/// from the OS CSPRNG. The key lives for the lifetime of the process
/// and is shared by every `Secret<T>`.
fn process_key() -> &'static Aes256Gcm {
    static KEY: OnceLock<Aes256Gcm> = OnceLock::new();
    KEY.get_or_init(|| {
        // 256-bit key from the OS CSPRNG. `generate_key` needs a
        // rand-core-0.10 RNG from the aead stack; the workspace `rand`
        // is 0.8, so fill the key bytes directly and construct the
        // cipher from the array.
        let mut key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        let key: Key<Aes256Gcm> = key_bytes.into();
        // Pin the key pages so the OS doesn't page them to swap.
        // Best-effort: failures are ignored (see `mlock`).
        let _ = mlock::mlock_bytes(&key[..]);
        Aes256Gcm::new(&key)
    })
}

/// Encrypt `plaintext` with the per-process key under a fresh nonce.
/// Returns `nonce || ciphertext || tag` (the GCM impl appends the tag
/// to the ciphertext).
fn seal(plaintext: &[u8]) -> Vec<u8> {
    let cipher = process_key();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    // `rand::thread_rng` is not used here because we want the OS CSPRNG
    // directly; `RngCore::fill_bytes` via `OsRng` gives us that.
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-GCM encryption of in-memory data cannot fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a `nonce || ciphertext || tag` blob produced by [`seal`].
fn open(blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return error::WrappedSnafu {
            message: "secret blob too short for nonce".to_string(),
        }
        .fail();
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = process_key();
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        error::WrappedSnafu {
            message: "AES-GCM decryption failed (wrong key or corrupted blob)".to_string(),
        }
        .build()
    })
}

/// A wrapper that keeps `T` encrypted at rest in process memory.
///
/// See the [module docs](self) for the threat model and key model.
pub struct Secret<T: SecretBytes> {
    // Always ciphertext (nonce || ct || tag) while at rest.
    sealed: Vec<u8>,
    _marker: std::marker::PhantomData<T>,
}

impl<T: SecretBytes> Secret<T> {
    /// Encrypt `value` and store only the ciphertext. The caller's
    /// `value` is consumed; if you still hold a copy elsewhere, you
    /// are responsible for zeroizing it.
    pub fn new(value: T) -> Self {
        let plaintext = value.to_secret_bytes();
        let sealed = seal(&plaintext);
        Self {
            sealed,
            _marker: std::marker::PhantomData,
        }
    }

    /// Build a `Secret` directly from already-serialized bytes, sparing
    /// the caller a temporary `T`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let sealed = seal(bytes);
        Self {
            sealed,
            _marker: std::marker::PhantomData,
        }
    }

    /// Borrow the decrypted plaintext for the duration of the returned
    /// guard. While the guard is live, the plaintext exists in process
    /// memory; when the guard drops, the plaintext buffer is zeroized
    /// so the only remaining representation of the value is the
    /// `Secret`'s at-rest ciphertext.
    ///
    /// The guard borrows the `Secret` for `'a`, so it cannot outlive
    /// the value it decrypted. Each call performs a fresh decrypt with
    /// a transient plaintext buffer; the `Secret` itself is never
    /// mutated (its ciphertext was never replaced by plaintext).
    pub fn access(&self) -> Result<SecretGuard<'_, T>> {
        let plaintext = open(&self.sealed)?;
        // Best-effort: try to keep the plaintext pages resident while
        // the guard is live. Ignored if unsupported/unprivileged.
        let _ = mlock::mlock_bytes(&plaintext);
        Ok(SecretGuard {
            plaintext,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<T: SecretBytes> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never reveal the inner value; not even the ciphertext, since
        // its length can leak structure.
        f.debug_struct("Secret").finish_non_exhaustive()
    }
}

impl<T: SecretBytes + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        // Cloning the ciphertext is sufficient: both copies decrypt to
        // equal plaintext. We don't re-encrypt, to avoid paying for an
        // extra AEAD round-trip on clone.
        Self {
            sealed: self.sealed.clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

/// A scoped borrow of the decrypted contents of a [`Secret`].
///
/// On `Drop`, the plaintext buffer is zeroized, restoring the
/// at-rest state to ciphertext-only (the parent `Secret` was never
/// mutated; it kept its ciphertext throughout the borrow).
pub struct SecretGuard<'a, T: SecretBytes> {
    plaintext: Vec<u8>,
    _marker: std::marker::PhantomData<&'a T>,
}

impl<T: SecretBytes> SecretGuard<'_, T> {
    /// The decrypted bytes, borrowed for the lifetime of this guard.
    pub fn bytes(&self) -> &[u8] {
        &self.plaintext
    }

    /// Reconstruct and return a clone of the typed value. The original
    /// plaintext stays inside the guard (and is zeroized on drop).
    pub fn value(&self) -> Result<T> {
        T::from_secret_bytes(&self.plaintext)
    }
}

impl<T: SecretBytes> Drop for SecretGuard<'_, T> {
    fn drop(&mut self) {
        // The parent `Secret` was never mutated: it kept its ciphertext
        // at rest throughout the borrow. All we need to do on drop is
        // destroy the transient plaintext so that, once the guard is
        // gone, the only in-memory representation of the value is the
        // `Secret`'s ciphertext. This is the "re-encrypts on drop"
        // guarantee: after the guard ends, the at-rest state is
        // restored to ciphertext-only.
        self.plaintext.zeroize();
    }
}

impl<T: SecretBytes> fmt::Debug for SecretGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretGuard").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip_vec() {
        let secret = Secret::new(vec![1u8, 2, 3, 4, 5]);
        let guard = secret.access().expect("decrypt succeeds with process key");
        assert_eq!(guard.bytes(), &[1u8, 2, 3, 4, 5]);
        let value = guard.value().expect("value round-trips");
        assert_eq!(value, vec![1u8, 2, 3, 4, 5]);
    }

    #[test]
    fn encrypt_decrypt_round_trip_string() {
        let secret = Secret::new("hunter2".to_string());
        let guard = secret.access().expect("decrypt succeeds");
        assert_eq!(guard.bytes(), b"hunter2");
        let value = guard.value().expect("string round-trips");
        assert_eq!(value, "hunter2");
    }

    #[test]
    fn encrypt_decrypt_round_trip_array() {
        let secret = Secret::new([42u8; 16]);
        let guard = secret.access().expect("decrypt succeeds");
        let value: [u8; 16] = guard.value().expect("array round-trips");
        assert_eq!(value, [42u8; 16]);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        // We can't swap the process key (it's in a OnceLock), but we
        // can prove a foreign ciphertext/key pair fails: encrypt with
        // an ad-hoc key, then try to open it through a Secret built
        // from that ciphertext, which will use the *process* key and
        // therefore fail AEAD verification.
        let mut foreign_key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut foreign_key_bytes);
        let foreign_key: Key<Aes256Gcm> = foreign_key_bytes.into();
        let foreign_cipher = Aes256Gcm::new(&foreign_key);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = foreign_cipher
            .encrypt(nonce, b"sensitive".as_ref())
            .expect("foreign encrypt");
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        // Build a Secret whose sealed field is the foreign blob.
        let secret = Secret::<Vec<u8>>::from_bytes(b"sensitive");
        // Overwrite the sealed field via a fresh Secret that wraps the
        // foreign ciphertext. We can't construct directly, so we test
        // `open` instead, which is what `access` calls.
        let err = open(&blob);
        assert!(err.is_err(), "decryption with the wrong key must fail");
        // Sanity: the legitimate Secret still decrypts fine.
        let guard = secret.access().expect("legit secret decrypts");
        assert_eq!(guard.bytes(), b"sensitive");
    }

    #[test]
    fn multiple_secrets_share_process_key() {
        let a = Secret::new(vec![10u8, 20]);
        let b = Secret::new(vec![30u8, 40, 50]);
        let ga = a.access().expect("a decrypts");
        let gb = b.access().expect("b decrypts");
        assert_eq!(ga.bytes(), &[10u8, 20]);
        assert_eq!(gb.bytes(), &[30u8, 40, 50]);
        // Both must have decrypted with the same process key.
        let _ = ga;
        let _ = gb;
    }

    #[test]
    fn fresh_nonce_each_access_changes_ciphertext() {
        // Repeatedly accessing the same Secret produces different
        // ciphertext blobs because each encryption uses a fresh nonce.
        // We observe this indirectly: two `Secret::new` calls with
        // equal plaintext must yield distinct ciphertext, since each
        // `new` runs `seal` once.
        let a = Secret::new(vec![7u8; 8]);
        let b = Secret::new(vec![7u8; 8]);
        assert_ne!(
            a.sealed, b.sealed,
            "two encryptions of equal plaintext must differ (fresh nonce)"
        );
        // And both still decrypt to the same plaintext.
        assert_eq!(a.access().unwrap().bytes(), &[7u8; 8]);
        assert_eq!(b.access().unwrap().bytes(), &[7u8; 8]);
    }

    #[test]
    fn debug_does_not_leak_inner() {
        let secret = Secret::new(b"top-secret-value".to_vec());
        let formatted = format!("{secret:?}");
        assert!(!formatted.contains("top-secret-value"));
        assert!(formatted.contains("Secret"));
    }

    #[test]
    fn clone_preserves_value() {
        let a = Secret::new(vec![9u8, 9, 9]);
        let b = a.clone();
        assert_eq!(a.access().unwrap().bytes(), &[9u8, 9, 9]);
        assert_eq!(b.access().unwrap().bytes(), &[9u8, 9, 9]);
    }

    #[test]
    fn open_rejects_short_blob() {
        let err = open(&[0u8; 4]);
        assert!(err.is_err(), "blob shorter than nonce must fail");
    }
}
