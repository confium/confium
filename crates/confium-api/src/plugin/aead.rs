//! `AeadPlugin` trait — the Rust-side counterpart of the AEAD v0 wire
//! protocol.
//!
//! Plugin authors implement this trait on their AEAD state type, then
//! apply `#[plugin_interface(name = "aead", version = 0)]` to the impl
//! block.
//!
//! Method → symbol mapping (see `crates/confium-core/src/ffi/aead.rs`
//! for the loader-side wire types):
//!
//! | trait method | FFI symbol | purpose |
//! |--------------|------------|---------|
//! | [`AeadPlugin::create_with_key`]      | `cfmp_aead_create`                    | construct a new instance |
//! | [`AeadPlugin::set_nonce`]            | `cfmp_aead_set_nonce`                 | set the nonce |
//! | [`AeadPlugin::associated_data_update`] | `cfmp_aead_associated_data_update` | absorb associated data |
//! | [`AeadPlugin::encrypt_update`]       | `cfmp_aead_encrypt_update`            | encrypt a chunk |
//! | [`AeadPlugin::decrypt_update`]       | `cfmp_aead_decrypt_update`            | decrypt a chunk |
//! | [`AeadPlugin::finalize`]             | `cfmp_aead_finalize`                  | emit the tag |
//! | [`AeadPlugin::verify_tag`]           | `cfmp_aead_verify_tag`                | verify the tag |
//! | `Drop`                               | `cfmp_aead_destroy`                   | reclaim the boxed state |

use crate::error::PluginResult;
use crate::options::OptionView;

/// Trait implemented by AEAD plugins.
pub trait AeadPlugin: Sized {
    /// Construct a new AEAD instance for the named algorithm with the
    /// given key.
    fn create_with_key(
        algorithm: &str,
        key: &[u8],
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<Self>;

    /// Set the nonce for this encryption/decryption session.
    fn set_nonce(&mut self, nonce: &[u8]) -> PluginResult<()>;

    /// Absorb associated (authenticated but not encrypted) data.
    fn associated_data_update(&mut self, data: &[u8]) -> PluginResult<()>;

    /// Encrypt a chunk of plaintext. Returns the number of bytes
    /// written to `output`.
    fn encrypt_update(&mut self, input: &[u8], output: &mut [u8]) -> PluginResult<usize>;

    /// Decrypt a chunk of ciphertext. Returns the number of bytes
    /// written to `output`.
    fn decrypt_update(&mut self, input: &[u8], output: &mut [u8]) -> PluginResult<usize>;

    /// Finalize and write the authentication tag into `tag`. Returns
    /// the number of bytes written.
    fn finalize(&mut self, tag: &mut [u8]) -> PluginResult<usize>;

    /// Verify the provided tag. Returns `Ok(())` if valid.
    fn verify_tag(&mut self, tag: &[u8]) -> PluginResult<()>;
}
