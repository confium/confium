//! Mock plugin built entirely with the `confium-api` SDK proc-macros.
//!
//! This is the proof-of-concept that the macro-generated FFI symbols
//! load through the standard Confium plugin loader. The plugin
//! implements two interfaces:
//!
//! - A trivial XOR-fold hash: the digest is one byte, the XOR of every
//!   input byte. Fully deterministic and dependency-free.
//! - A trivial XOR-stream cipher: each input byte is XOR-folded with a
//!   running key byte derived from the key material. The cipher is a
//!   stand-in for a real symmetric cipher — it exercises the full
//!   `cfmp_cipher_*` symbol set (create, block/key/iv size, update,
//!   finalize, reset, destroy) end to end.
//!
//! The crate compiles to a `cdylib` so the loader can `dlopen` it.
//! The `cfmp_*` symbols are emitted by:
//!
//! - `#[plugin_interface(name = "hash", version = 0)]` on the
//!   `impl HashPlugin for XorHash` block (eight `cfmp_hash_*` symbols).
//! - `#[plugin_interface(name = "cipher", version = 0)]` on the
//!   `impl CipherPlugin for XorCipher` block (eight `cfmp_cipher_*`
//!   symbols).
//! - `#[export(metadata(...))]` on the plugin marker struct. Emits the
//!   lifecycle + metadata symbols. The interface list is auto-discovered
//!   from the `#[plugin_interface]` attributes above; no explicit
//!   `interfaces(...)` argument is needed.
//!
//! The integration test in `tests/loader.rs` loads this crate's
//! cdylib artifact and runs an end-to-end hash and cipher through the
//! loader.

use confium_api::CipherPlugin;
use confium_api::HashPlugin;
use confium_api::error::PluginResult;
use confium_api::options::OptionView;
use confium_macros::{export, plugin_interface};

// =====================================================================
// Hash interface — XOR-fold hash
// =====================================================================

/// One-byte XOR-fold hash. State is a single accumulator byte.
pub struct XorHash {
    acc: u8,
}

impl XorHash {
    /// Construct an empty accumulator. Exposed for tests that want to
    /// bypass the trait `create_with_opts` path.
    pub fn new() -> Self {
        Self { acc: 0 }
    }
}

impl Default for XorHash {
    fn default() -> Self {
        Self::new()
    }
}

#[plugin_interface(name = "hash", version = 0)]
impl HashPlugin for XorHash {
    fn create_with_opts(_name: &str, _opts: Option<OptionView<'_>>) -> PluginResult<Self> {
        Ok(Self::new())
    }

    fn output_size(&self) -> u32 {
        1
    }

    fn block_size(&self) -> u32 {
        // The XOR hash has no meaningful block size. Return 1 so callers
        // that try to chunk input still make progress.
        1
    }

    fn update(&mut self, data: &[u8]) -> PluginResult<()> {
        for &b in data {
            self.acc ^= b;
        }
        Ok(())
    }

    fn reset(&mut self) -> PluginResult<()> {
        self.acc = 0;
        Ok(())
    }

    fn try_clone(&self) -> PluginResult<Self> {
        Ok(Self { acc: self.acc })
    }

    fn finalize(&mut self, out: &mut [u8]) -> PluginResult<()> {
        if out.is_empty() {
            return Err(confium_api::PluginError::new(
                confium_api::ErrorCode::INSUFFICIENT_BUFFER,
                "xor hash needs at least 1 byte of output buffer",
            ));
        }
        out[0] = self.acc;
        Ok(())
    }
}

// =====================================================================
// Cipher interface — XOR-stream cipher
// =====================================================================

/// Trivial XOR-stream cipher used as a mock. The "key schedule" is a
/// single running byte derived by XOR-folding the supplied key; each
/// input byte is XORed with that running byte. This is not secure
/// cryptography — it exists only to exercise the full cipher FFI
/// surface without pulling in a real cipher library.
pub struct XorCipher {
    /// The running key byte. XORed against every input byte.
    keystream: u8,
}

impl XorCipher {
    /// Construct from key + iv. The key is XOR-folded into a single
    /// byte; the IV is folded in on top so different IVs produce
    /// different keystreams for the same key.
    pub fn from_key_iv(key: &[u8], iv: &[u8]) -> Self {
        let mut k: u8 = 0;
        for &b in key {
            k ^= b;
        }
        for &b in iv {
            k ^= b;
        }
        Self { keystream: k }
    }
}

#[plugin_interface(name = "cipher", version = 0)]
impl CipherPlugin for XorCipher {
    fn create_with_key(
        _algorithm: &str,
        key: &[u8],
        iv: &[u8],
        _opts: Option<OptionView<'_>>,
    ) -> PluginResult<Self> {
        Ok(Self::from_key_iv(key, iv))
    }

    fn block_size(&self) -> u32 {
        // A stream cipher has no meaningful block size. Return 1 so the
        // loader's buffer-allocation logic doesn't divide by zero.
        1
    }

    fn key_size(&self) -> u32 {
        // The mock accepts any key length; report 0 to signal "variable".
        0
    }

    fn iv_size(&self) -> u32 {
        // The mock accepts any IV length; report 0 to signal "variable".
        0
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> PluginResult<usize> {
        let n = input.len().min(output.len());
        for i in 0..n {
            output[i] = input[i] ^ self.keystream;
        }
        Ok(n)
    }

    fn finalize(&mut self, _output: &mut [u8]) -> PluginResult<usize> {
        // A stream cipher has no buffered final block.
        Ok(0)
    }

    fn reset(&mut self) -> PluginResult<()> {
        // Reset is a no-op for this mock: the keystream byte is derived
        // from the key, not from accumulated state.
        Ok(())
    }
}

// `#[export]` emits the four plugin lifecycle symbols plus the optional
// `cfmp_metadata` symbol (because `metadata(...)` is supplied). The
// interface list is auto-discovered from the `#[plugin_interface]`
// attributes above — `hash` and `symmetric` (cipher's wire name) are
// registered at link time and surfaced through
// `cfmp_query_interfaces` without an explicit `interfaces(...)` arg.
#[export(metadata(
    name = "confium-mock-plugin",
    version = "0.1.0",
    vendor = "confium",
    license = "BSD-2-Clause",
    description = "XOR-fold mock hash + cipher for SDK loader tests",
))]
pub struct Plugin;
