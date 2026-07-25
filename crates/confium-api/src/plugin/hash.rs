//! `HashPlugin` trait — the Rust-side counterpart of the hash v0 wire
//! protocol.
//!
//! Plugin authors implement this trait on their hash state type, then
//! apply `#[plugin_interface(name = "hash", version = 0)]` to the impl
//! block. The macro emits the eight canonical `cfmp_hash_*` FFI symbols,
//! one per trait method.
//!
//! Method → symbol mapping (see `crates/confium-core/src/ffi/hash.rs`
//! for the loader-side wire types):
//!
//! | trait method | FFI symbol | purpose |
//! |--------------|------------|---------|
//! | [`HashPlugin::create_with_opts`] | `cfmp_hash_create`         | construct a new instance |
//! | [`HashPlugin::output_size`]      | `cfmp_hash_output_size`    | output length in bytes |
//! | [`HashPlugin::block_size`]       | `cfmp_hash_block_size`     | internal block size in bytes |
//! | [`HashPlugin::update`]           | `cfmp_hash_update`         | absorb input bytes |
//! | [`HashPlugin::reset`]            | `cfmp_hash_reset`          | reset to initial state |
//! | [`HashPlugin::try_clone`]        | `cfmp_hash_clone`          | duplicate the state |
//! | [`HashPlugin::finalize`]         | `cfmp_hash_finalize`       | emit digest into caller buffer |
//! | `Drop`                           | `cfmp_hash_destroy`        | reclaim the boxed state |

use crate::error::{PluginError, PluginResult};
use crate::options::OptionView;

/// Trait implemented by hash plugins. The macro-generated
/// `cfmp_hash_create` calls [`HashPlugin::create_with_opts`]; all other
/// symbols dispatch through `OpaqueHandle::<Self>::borrow_raw` and the
/// corresponding trait method.
///
/// `update`, `reset`, `try_clone`, and `finalize` may return a
/// [`PluginError`]; the macro maps the error into the wire status code
/// (non-zero) that the loader surfaces via its `Error::PluginInternalError`
/// variant.
pub trait HashPlugin: Sized {
    /// Construct a new hash instance for the named algorithm.
    ///
    /// `name` is the algorithm name the caller passed to
    /// `cfm_hash_create` (e.g. `"sha-256"`). `opts` is the caller's
    /// option map (or `None` if the caller passed NULL). Plugins that
    /// don't take options can ignore both.
    fn create_with_opts(name: &str, opts: Option<OptionView<'_>>) -> PluginResult<Self>;

    /// Output length in bytes for this instance. The caller allocates a
    /// buffer of this size before calling `finalize`.
    fn output_size(&self) -> u32;

    /// Internal block size in bytes. Used by callers that want to feed
    /// input in aligned chunks; safe to return a constant (e.g. 64) if
    /// the algorithm doesn't have a meaningful block size.
    fn block_size(&self) -> u32;

    /// Absorb `data` into the hash state.
    fn update(&mut self, data: &[u8]) -> PluginResult<()>;

    /// Reset to the initial state (post-`create`).
    fn reset(&mut self) -> PluginResult<()>;

    /// Duplicate the hash state. The clone must be independent: updates
    /// to one must not affect the other.
    fn try_clone(&self) -> PluginResult<Self>;

    /// Write the finalized digest into `out`. The caller guarantees
    /// `out.len() == self.output_size()`. Plugins that need to pad or
    /// finalize internally should do so here.
    fn finalize(&mut self, out: &mut [u8]) -> PluginResult<()>;
}

/// Trivial constructor entry point for plugin authors who don't need
/// `opts`. Wraps [`HashPlugin::create_with_opts`] with `None`.
///
/// Plugin authors do not normally call this — the macro-generated
/// `cfmp_hash_create` calls `create_with_opts` directly. It's provided
/// as a convenience for tests and hand-written plugins.
pub fn create_simple<T: HashPlugin>(name: &str) -> PluginResult<T> {
    T::create_with_opts(name, None)
}

/// Default `block_size` implementation for hash plugins that don't have
/// a meaningful block size. Returns 64, the common block size for
/// SHA-2 family hashes.
pub fn default_block_size() -> u32 {
    64
}

#[doc(hidden)]
/// Convenience used by macro-generated code to convert a `Result<T, E>`
/// where `E: ToString` into a [`PluginResult<T>`].
pub fn err_with_message<E: std::fmt::Display>(code: crate::ErrorCode, e: E) -> PluginError {
    PluginError::new(code, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial XOR-fold hash used by the test suite. Each byte of
    /// input is XOR-folded into a single u8 state; `finalize` writes
    /// that single byte to the first byte of the output buffer.
    struct XorHash {
        acc: u8,
    }

    impl HashPlugin for XorHash {
        fn create_with_opts(_name: &str, _opts: Option<OptionView<'_>>) -> PluginResult<Self> {
            Ok(XorHash { acc: 0 })
        }

        fn output_size(&self) -> u32 {
            1
        }

        fn block_size(&self) -> u32 {
            default_block_size()
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
            Ok(XorHash { acc: self.acc })
        }

        fn finalize(&mut self, out: &mut [u8]) -> PluginResult<()> {
            if out.is_empty() {
                return Err(crate::error::PluginError::new(
                    crate::ErrorCode::INSUFFICIENT_BUFFER,
                    "output buffer too small",
                ));
            }
            out[0] = self.acc;
            Ok(())
        }
    }

    #[test]
    fn xor_hash_produces_xor_of_inputs() {
        let mut h = XorHash::create_with_opts("xor", None).unwrap();
        h.update(&[1, 2, 4]).unwrap();
        let mut out = [0u8];
        h.finalize(&mut out).unwrap();
        assert_eq!(out[0], 1 ^ 2 ^ 4);
    }

    #[test]
    fn xor_hash_clone_is_independent() {
        let mut a = XorHash::create_with_opts("xor", None).unwrap();
        a.update(&[0xFF]).unwrap();
        let mut b = a.try_clone().unwrap();
        a.update(&[0x01]).unwrap();
        b.update(&[0x02]).unwrap();
        let mut oa = [0u8];
        let mut ob = [0u8];
        a.finalize(&mut oa).unwrap();
        b.finalize(&mut ob).unwrap();
        assert_eq!(oa[0], 0xFF ^ 0x01);
        assert_eq!(ob[0], 0xFF ^ 0x02);
    }

    #[test]
    fn xor_hash_reset_clears_state() {
        let mut h = XorHash::create_with_opts("xor", None).unwrap();
        h.update(&[0xFF]).unwrap();
        h.reset().unwrap();
        let mut out = [0u8];
        h.finalize(&mut out).unwrap();
        assert_eq!(out[0], 0);
    }
}
