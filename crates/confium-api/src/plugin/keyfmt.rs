//! `KeyfmtPlugin` trait — the Rust-side counterpart of the key
//! serialization (keyfmt) v0 wire protocol.
//!
//! Plugin authors implement this trait on their key representation
//! type, then apply `#[plugin_interface(name = "keyfmt", version = 0)]`
//! to the impl block.
//!
//! See `crates/confium-core/src/ffi/keyfmt.rs` for the loader-side
//! wire types.

use crate::error::PluginResult;
use crate::options::OptionView;

/// What kind of key this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyKind {
    /// Secret key (private material present).
    Secret = 0,
    /// Public key only (no private material).
    Public = 1,
    /// Both secret and public material.
    Both = 2,
}

/// Trait implemented by key-format plugins. The type `Self` is the
/// parsed key representation; `parse` constructs it from bytes and
/// `serialize` writes it back out.
pub trait KeyfmtPlugin: Sized {
    /// Parse `bytes` in the named `format` into a key object. The
    /// `algorithm_hint` may guide format-specific parsing (e.g. for
    /// `Raw` format).
    fn parse(
        format: &str,
        algorithm_hint: Option<&str>,
        bytes: &[u8],
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<Self>;

    /// Serialize the key into the named `format`. Returns the bytes.
    fn serialize(&self, format: &str) -> PluginResult<Vec<u8>>;

    /// Report whether this key is secret, public, or both.
    fn kind(&self) -> PluginResult<KeyKind>;

    /// Report the algorithm name for this key.
    fn algorithm(&self) -> PluginResult<String>;

    /// Produce a public-only view of this key (stripping secret
    /// material). The returned value is a new boxed key object.
    fn public(&self) -> PluginResult<Self>;
}
