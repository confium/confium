//! `RngPlugin` trait — the Rust-side counterpart of the RNG v0 wire
//! protocol.
//!
//! Plugin authors implement this trait on their RNG state type, then
//! apply `#[plugin_interface(name = "rng", version = 0)]` to the impl
//! block.
//!
//! Method → symbol mapping (see `crates/confium-core/src/ffi/rng.rs`
//! for the loader-side wire types):
//!
//! | trait method | FFI symbol | purpose |
//! |--------------|------------|---------|
//! | [`RngPlugin::create`]      | `cfmp_rng_create`       | construct a new instance |
//! | [`RngPlugin::reseed`]      | `cfmp_rng_reseed`       | reseed from entropy |
//! | [`RngPlugin::add_entropy`] | `cfmp_rng_add_entropy`  | add entropy |
//! | [`RngPlugin::generate`]    | `cfmp_rng_generate`     | generate random bytes |
//! | `Drop`                     | `cfmp_rng_destroy`      | reclaim the boxed state |

use crate::error::PluginResult;
use crate::options::OptionView;

/// Trait implemented by RNG plugins.
pub trait RngPlugin: Sized {
    /// Construct a new RNG instance for the named algorithm.
    fn create(algorithm: &str, opts: Option<OptionView<'_>>) -> PluginResult<Self>;

    /// Reseed the generator from the provided entropy.
    fn reseed(&mut self, data: &[u8]) -> PluginResult<()>;

    /// Add entropy without a full reseed.
    fn add_entropy(&mut self, data: &[u8]) -> PluginResult<()>;

    /// Fill `out` with random bytes.
    fn generate(&mut self, out: &mut [u8]) -> PluginResult<()>;
}
