//! Mock hash plugin built entirely with the `confium-api` SDK
//! proc-macros.
//!
//! This is the proof-of-concept that the macro-generated FFI symbols
//! load through the standard Confium plugin loader. The plugin
//! implements a trivial XOR-fold hash: the digest is one byte, the XOR
//! of every input byte. It is fully deterministic and dependency-free,
//! which makes it suitable as a workspace test fixture that doesn't
//! require Botan to be installed.
//!
//! The crate compiles to a `cdylib` so the loader can `dlopen` it.
//! The `cfmp_*` symbols are emitted by:
//!
//! - `#[plugin_interface(name = "hash", version = 0)]` on the
//!   `impl HashPlugin for XorHash` block (eight `cfmp_hash_*` symbols).
//! - `#[export(interfaces(hash = 0), metadata(...))]` on the plugin
//!   marker struct (lifecycle + metadata symbols).
//!
//! The integration test in `tests/loader.rs` loads this crate's
//! cdylib artifact and runs an end-to-end hash through the loader.

use confium_api::HashPlugin;
use confium_api::error::PluginResult;
use confium_api::options::OptionView;
use confium_macros::{export, plugin_interface};

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

// `#[export]` emits the four plugin lifecycle symbols plus the optional
// `cfmp_metadata` symbol (because `metadata(...)` is supplied). The
// `interfaces(hash = 0)` argument populates the
// `cfmp_query_interfaces` payload so the loader knows to negotiate the
// hash v0 interface with this plugin.
#[export(
    interfaces(hash = 0),
    metadata(
        name = "confium-mock-plugin",
        version = "0.1.0",
        vendor = "confium",
        license = "BSD-2-Clause",
        description = "XOR-fold mock hash for SDK loader tests",
    )
)]
pub struct Plugin;
