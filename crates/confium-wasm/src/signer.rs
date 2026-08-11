//! WASI-target signer surface for the Confium WASM package.
//!
//! Enabled via the `sign` Cargo feature. Targets `wasm32-wasip1`
//! (or `wasm32-wasip2`). Hosts: Cloudflare Workers, Fastly
//! Compute@Edge, Vercel Edge Functions, Deno, Bun, Wasmtime, Wasmer,
//! WasmEdge.
//!
//! ## Why a separate WASM signer?
//!
//! The default browser-target build (`wasm32-unknown-unknown`) is
//! verifier-only because:
//!
//! 1. **Threat model** — browser code is hostile; secret keys
//!    shouldn't live there.
//! 2. **No OsRng** — `wasm32-unknown-unknown` doesn't expose
//!    cryptographic randomness from the host.
//!
//! WASI hosts flip both: edge workers run trusted code, and WASI
//! exposes the host's `/dev/urandom` via `random_get`. The same
//! Confium Rust code that powers server-side signing runs in any
//! WASI host with no FFI overhead.
//!
//! ## Build
//!
//! ```sh
//! rustup target add wasm32-wasip1
//! cargo build --target wasm32-wasip1 --features sign --release
//! wasm-tools component new target/wasm32-wasip1/release/confium_wasm.wasm \
//!     -o confium.wasm --adapt wasi_snapshot_preview1.wasm
//! ```
//!
//! ## Quickstart (Cloudflare Workers shape)
//!
//! ```typescript
//! import { Cmp20Signer } from "@confium/confium-wasm/signer";
//!
//! export default {
//!   async fetch(req: Request): Promise<Response> {
//!     const { shares, threshold, message } = await req.json();
//!     const signer = new Cmp20Signer();
//!     const sig = signer.sign(shares, threshold, message);
//!     return new Response(sig);
//!   },
//! };
//! ```

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

fn map_err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// CMP20 in-process threshold-ECDSA signer.
///
/// Construct fresh per signing ceremony; do not reuse across
/// ceremonies because the in-process driver holds session state
/// that's specific to one DKG + sign cycle.
#[wasm_bindgen]
pub struct Cmp20Signer;

#[wasm_bindgen]
impl Cmp20Signer {
    /// Run a non-interactive CMP20 DKG for `party_count` parties at
    /// `threshold`. Returns a JS object `{shares: Uint8Array[],
    /// publicKey: Uint8Array}`.
    #[wasm_bindgen]
    pub fn keygen(&self, threshold: u32, party_count: u32) -> Result<JsValue, JsValue> {
        let kg = confium_tc_cmp20::inprocess::keygen(threshold, party_count as usize)
            .map_err(map_err)?;
        let obj = js_sys::Object::new();
        let shares = js_sys::Array::new();
        for s in kg.shares {
            shares.push(&Uint8Array::from(s.as_slice()));
        }
        js_sys::Reflect::set(&obj, &"shares".into(), &shares)?;
        js_sys::Reflect::set(
            &obj,
            &"publicKey".into(),
            &Uint8Array::from(kg.public_key.as_slice()),
        )?;
        Ok(obj.into())
    }

    /// Threshold-sign `message` with `shares` (Array of Uint8Array)
    /// at `threshold`. Returns a 64-byte `Uint8Array`.
    #[wasm_bindgen]
    pub fn sign(
        &self,
        shares: &js_sys::Array,
        threshold: u32,
        message: &[u8],
    ) -> Result<Uint8Array, JsValue> {
        let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(shares.length() as usize);
        for i in 0..shares.length() {
            let buf: Uint8Array = shares.get(i).into();
            blobs.push(buf.to_vec());
        }
        let sig = confium_tc_cmp20::inprocess::sign(&blobs, threshold, message).map_err(map_err)?;
        Ok(Uint8Array::from(sig.as_slice()))
    }
}

impl Default for Cmp20Signer {
    fn default() -> Self {
        Self
    }
}

/// GG18 in-process threshold-ECDSA signer. Prefer `Cmp20Signer` for
/// new deployments.
#[wasm_bindgen]
pub struct Gg18Signer;

#[wasm_bindgen]
impl Gg18Signer {
    /// Run a GG18 DKG.
    #[wasm_bindgen]
    pub fn keygen(&self, threshold: u32, party_count: u32) -> Result<JsValue, JsValue> {
        let kg =
            confium_tc_gg18::inprocess::keygen(threshold, party_count as usize).map_err(map_err)?;
        let obj = js_sys::Object::new();
        let shares = js_sys::Array::new();
        for s in kg.shares {
            shares.push(&Uint8Array::from(s.as_slice()));
        }
        js_sys::Reflect::set(&obj, &"shares".into(), &shares)?;
        js_sys::Reflect::set(
            &obj,
            &"publicKey".into(),
            &Uint8Array::from(kg.public_key.as_slice()),
        )?;
        Ok(obj.into())
    }

    /// Threshold-sign `message` with `shares` at `threshold`.
    #[wasm_bindgen]
    pub fn sign(
        &self,
        shares: &js_sys::Array,
        threshold: u32,
        message: &[u8],
    ) -> Result<Uint8Array, JsValue> {
        let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(shares.length() as usize);
        for i in 0..shares.length() {
            let buf: Uint8Array = shares.get(i).into();
            blobs.push(buf.to_vec());
        }
        let sig = confium_tc_gg18::inprocess::sign(&blobs, threshold, message).map_err(map_err)?;
        Ok(Uint8Array::from(sig.as_slice()))
    }
}

impl Default for Gg18Signer {
    fn default() -> Self {
        Self
    }
}
