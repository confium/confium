//! Confium Node.js bindings — threshold cryptography for server-side JS.
//!
//! Wraps the in-process DKG + sign drivers from
//! [`confium_tc_cmp20`]/[`confium_tc_gg18`], plus the FROST-P256
//! Shamir primitives and ElGamal-P256 threshold encryption. Output
//! shapes mirror the Ruby + Python bindings so cross-binding parity
//! tests work uniformly.
//!
//! ## Why Node.js when WASM exists?
//!
//! The [`@confium/confium-wasm`](https://www.npmjs.com/package/@confium/confium-wasm)
//! package is **verifier-only by design** — browsers verify,
//! servers sign. Node.js is server-side. This binding exposes the
//! *signing* surface for Node consumers: CI release pipelines,
//! signing microservices, scheduled-ceremony workers.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use napi::bindgen_prelude::Buffer;
use napi::bindgen_prelude::Result as NapiResult;
use napi_derive::napi;

fn map_err<E: std::fmt::Display>(e: E) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, e.to_string())
}

// ===== CMP20 =====

/// CMP20 threshold-ECDSA over P-256. Use for new threshold signing
/// deployments; GG18 is provided for interop with existing systems.
#[napi]
pub struct Cmp20;

#[napi]
impl Cmp20 {
    /// Run a non-interactive CMP20 DKG for `party_count` parties at
    /// threshold `threshold`. Returns the per-party share blobs and
    /// the joint SEC1-compressed public key.
    #[napi]
    pub fn keygen(threshold: u32, party_count: u32) -> NapiResult<Cmp20Keygen> {
        let kg = confium_tc_cmp20::inprocess::keygen(threshold, party_count as usize)
            .map_err(map_err)?;
        Ok(Cmp20Keygen {
            shares: kg.shares.into_iter().map(Into::into).collect(),
            public_key: kg.public_key.into(),
        })
    }

    /// Threshold-sign `message` using `shares` (each a share blob from
    /// a previous `keygen` call). Returns the 64-byte `(r, s)` signature.
    #[napi]
    pub fn sign(shares: Vec<Buffer>, threshold: u32, message: Buffer) -> NapiResult<Buffer> {
        let share_blobs: Vec<Vec<u8>> = shares.into_iter().map(|b| b.to_vec()).collect();
        let msg = message.to_vec();
        let sig = confium_tc_cmp20::inprocess::sign(&share_blobs, threshold, &msg)
            .map_err(map_err)?;
        Ok(sig.into())
    }

    /// Sign N messages against the same joint key without re-running
    /// DKG. See `sign_batch` in the Rust crate for performance notes.
    #[napi]
    pub fn sign_batch(
        shares: Vec<Buffer>,
        threshold: u32,
        messages: Vec<Buffer>,
    ) -> NapiResult<Vec<Buffer>> {
        let share_blobs: Vec<Vec<u8>> = shares.into_iter().map(|b| b.to_vec()).collect();
        let msg_refs: Vec<&[u8]> = messages.iter().map(|b| b.as_ref()).collect();
        let sigs =
            confium_tc_cmp20::inprocess::sign_batch(&share_blobs, threshold, &msg_refs)
                .map_err(map_err)?;
        Ok(sigs.into_iter().map(Into::into).collect())
    }
}

/// Outcome of a CMP20 / GG18 DKG.
#[napi(object)]
pub struct Cmp20Keygen {
    /// Per-party share blobs, 71 bytes each. Distribute to N parties.
    pub shares: Vec<Buffer>,
    /// Joint P-256 public key (SEC1 compressed, 33 bytes).
    #[napi(js_name = "publicKey")]
    pub public_key: Buffer,
}

// ===== GG18 =====

/// GG18 threshold-ECDSA over P-256. Prefer `Cmp20` for new deployments.
#[napi]
pub struct Gg18;

#[napi]
impl Gg18 {
    /// Run a GG18 DKG. Returns the same shape as `Cmp20.keygen`.
    #[napi]
    pub fn keygen(threshold: u32, party_count: u32) -> NapiResult<Cmp20Keygen> {
        let kg = confium_tc_gg18::inprocess::keygen(threshold, party_count as usize)
            .map_err(map_err)?;
        Ok(Cmp20Keygen {
            shares: kg.shares.into_iter().map(Into::into).collect(),
            public_key: kg.public_key.into(),
        })
    }

    /// Threshold-sign `message` with `shares`. Returns the 64-byte `(r, s)` signature.
    #[napi]
    pub fn sign(shares: Vec<Buffer>, threshold: u32, message: Buffer) -> NapiResult<Buffer> {
        let share_blobs: Vec<Vec<u8>> = shares.into_iter().map(|b| b.to_vec()).collect();
        let msg = message.to_vec();
        let sig = confium_tc_gg18::inprocess::sign(&share_blobs, threshold, &msg)
            .map_err(map_err)?;
        Ok(sig.into())
    }
}

// ===== FROST-P256 (Shamir + single-party ECDSA) =====

/// FROST-P256 Shamir primitives + single-party ECDSA-P256 sign.
#[napi]
pub struct FrostP256;

#[napi]
impl FrostP256 {
    /// Generate a fresh P-256 keypair. Returns `{privateKey, publicKey}`
    /// as 32-byte + 65-byte buffers respectively.
    #[napi]
    pub fn generate_keypair() -> NapiResult<FrostKeypair> {
        let kp = confium_tc_frost_p256::generate_keypair();
        let sk: [u8; 32] = kp.to_signing_key().to_bytes().into();
        let pk = kp.to_verifying_key().to_sec1_bytes();
        Ok(FrostKeypair {
            private_key: sk.to_vec().into(),
            public_key: pk.to_vec().into(),
        })
    }
}

/// Outcome of `FrostP256.generateKeypair`.
#[napi(object)]
pub struct FrostKeypair {
    /// 32-byte secret scalar.
    #[napi(js_name = "privateKey")]
    pub private_key: Buffer,
    /// 65-byte SEC1 uncompressed public key.
    #[napi(js_name = "publicKey")]
    pub public_key: Buffer,
}

// ===== Version =====

/// Package version (mirrors the Cargo version).
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
