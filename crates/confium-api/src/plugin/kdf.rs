//! `KdfPlugin` trait — the Rust-side counterpart of the KDF v0 wire
//! protocol.
//!
//! Plugin authors implement this trait on their KDF state type, then
//! apply `#[plugin_interface(name = "kdf", version = 0)]` to the impl
//! block.
//!
//! Method → symbol mapping (see `crates/confium-core/src/ffi/kdf.rs`
//! for the loader-side wire types):
//!
//! | trait method | FFI symbol | purpose |
//! |--------------|------------|---------|
//! | [`KdfPlugin::create`]               | `cfmp_kdf_create`             | construct a new instance |
//! | [`KdfPlugin::set_salt`]             | `cfmp_kdf_set_salt`           | set the salt |
//! | [`KdfPlugin::set_iterations`]       | `cfmp_kdf_set_iterations`     | set iteration count |
//! | [`KdfPlugin::set_memory_cost`]      | `cfmp_kdf_set_memory_cost`    | set memory cost |
//! | [`KdfPlugin::set_parallelism`]      | `cfmp_kdf_set_parallelism`    | set parallelism |
//! | [`KdfPlugin::set_hash`]             | `cfmp_kdf_set_hash`           | set hash algorithm |
//! | [`KdfPlugin::derive`]               | `cfmp_kdf_derive`             | derive key material |
//! | `Drop`                              | `cfmp_kdf_destroy`            | reclaim the boxed state |

use crate::error::PluginResult;
use crate::options::OptionView;

/// Trait implemented by KDF plugins.
pub trait KdfPlugin: Sized {
    /// Construct a new KDF instance for the named algorithm.
    fn create(algorithm: &str, opts: Option<OptionView<'_>>) -> PluginResult<Self>;

    /// Set the salt.
    fn set_salt(&mut self, salt: &[u8]) -> PluginResult<()>;

    /// Set the iteration count.
    fn set_iterations(&mut self, iterations: u32) -> PluginResult<()>;

    /// Set the memory cost in bytes.
    fn set_memory_cost(&mut self, bytes: u64) -> PluginResult<()>;

    /// Set the parallelism (number of lanes).
    fn set_parallelism(&mut self, lanes: u32) -> PluginResult<()>;

    /// Set the hash algorithm name.
    fn set_hash(&mut self, hash_name: &str) -> PluginResult<()>;

    /// Derive `out.len()` bytes of key material from `input`.
    fn derive(&mut self, input: &[u8], out: &mut [u8]) -> PluginResult<()>;
}
