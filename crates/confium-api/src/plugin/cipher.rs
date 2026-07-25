//! `CipherPlugin` trait — the Rust-side counterpart of the symmetric
//! cipher v0 wire protocol.
//!
//! Plugin authors implement this trait on their cipher state type, then
//! apply `#[plugin_interface(name = "cipher", version = 0)]` to the impl
//! block. The macro emits the eight canonical `cfmp_cipher_*` FFI symbols,
//! one per trait method.
//!
//! Method → symbol mapping (see `crates/confium-core/src/ffi/cipher.rs`
//! for the loader-side wire types):
//!
//! | trait method | FFI symbol | purpose |
//! |--------------|------------|---------|
//! | [`CipherPlugin::create_with_key`] | `cfmp_cipher_create`       | construct a new instance |
//! | [`CipherPlugin::block_size`]      | `cfmp_cipher_block_size`   | block size in bytes |
//! | [`CipherPlugin::key_size`]        | `cfmp_cipher_key_size`     | key length in bytes |
//! | [`CipherPlugin::iv_size`]         | `cfmp_cipher_iv_size`      | nonce/IV length in bytes |
//! | [`CipherPlugin::update`]          | `cfmp_cipher_update`       | encrypt/decrypt a chunk |
//! | [`CipherPlugin::finalize`]        | `cfmp_cipher_finalize`     | flush remaining output |
//! | [`CipherPlugin::reset`]           | `cfmp_cipher_reset`        | reset to initial state |
//! | `Drop`                            | `cfmp_cipher_destroy`      | reclaim the boxed state |

use crate::error::{PluginError, PluginResult};
use crate::options::OptionView;

/// Trait implemented by symmetric cipher plugins. The macro-generated
/// `cfmp_cipher_create` calls [`CipherPlugin::create_with_key`]; all
/// other symbols dispatch through `OpaqueHandle::<Self>::borrow_raw`
/// and the corresponding trait method.
pub trait CipherPlugin: Sized {
    /// Construct a new cipher instance for the named algorithm with the
    /// given key and IV. Either `key` or `iv` may be empty when the
    /// algorithm does not require them.
    fn create_with_key(
        algorithm: &str,
        key: &[u8],
        iv: &[u8],
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<Self>;

    /// Block size in bytes for this instance.
    fn block_size(&self) -> u32;

    /// Key length in bytes for this instance's algorithm.
    fn key_size(&self) -> u32;

    /// IV / nonce length in bytes for this instance's algorithm.
    fn iv_size(&self) -> u32;

    /// Process `input` and write as many output bytes as fit into
    /// `output`. Returns the number of bytes written. The caller
    /// guarantees `output.len()` is large enough to hold one block of
    /// ciphertext per block of input.
    fn update(&mut self, input: &[u8], output: &mut [u8]) -> PluginResult<usize>;

    /// Flush any buffered output (e.g. the final partial block after
    /// padding) into `output`. Returns the number of bytes written.
    fn finalize(&mut self, output: &mut [u8]) -> PluginResult<usize>;

    /// Reset to the initial state (post-`create`).
    fn reset(&mut self) -> PluginResult<()>;
}

/// Convenience used by macro-generated code to surface a buffer-too-small
/// condition as a [`PluginError`] without repeating the boilerplate at
/// every call site.
pub fn insufficient_buffer(message: &str) -> PluginError {
    PluginError::new(crate::ErrorCode::INSUFFICIENT_BUFFER, message)
}
