//! `SignaturePlugin` trait — the Rust-side counterpart of the
//! asymmetric signature v0 wire protocol.
//!
//! The signature interface has three object types: a signer (holds the
//! secret key), a verifier (holds the public key), and a keypair
//! generator. A single plugin implements all three.
//!
//! Plugin authors implement this trait on a state type that represents
//! the signer/verifier context, then apply
//! `#[plugin_interface(name = "signature", version = 0)]` to the impl
//! block.
//!
//! The FFI surface splits symbols into `cfmp_sig_signer_*`,
//! `cfmp_sig_verifier_*`, and `cfmp_sig_keypair_generate`. The trait
//! methods map to these symbols.
//!
//! See `crates/confium-core/src/ffi/signature.rs` for the loader-side
//! wire types.

use crate::error::PluginResult;
use crate::options::OptionView;

/// A keypair generation result.
pub struct SignatureKeypair {
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Secret key bytes.
    pub secret_key: Vec<u8>,
}

/// Trait implemented by signature plugins. The type `Self` serves as
/// both the signer and verifier state — the plugin dispatches
/// internally based on which entry points are called.
pub trait SignaturePlugin: Sized {
    /// Construct a signer from the secret key.
    fn signer_create(
        algorithm: &str,
        secret_key: &[u8],
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<Self>;

    /// Construct a verifier from the public key.
    fn verifier_create(
        algorithm: &str,
        public_key: &[u8],
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<Self>;

    /// Set the hash algorithm used for signing/verifying (for
    /// hash-then-sign schemes).
    fn set_hash(&mut self, hash_name: &str) -> PluginResult<()>;

    /// Absorb message bytes into the signing/verification context.
    fn update(&mut self, data: &[u8]) -> PluginResult<()>;

    /// Finalize signing: write the signature into `sig_out`. Returns
    /// the number of bytes written.
    fn signer_finalize(&mut self, sig_out: &mut [u8]) -> PluginResult<usize>;

    /// Finalize verification: return `Ok(())` if the signature is
    /// valid.
    fn verifier_finalize(&mut self, signature: &[u8]) -> PluginResult<()>;

    /// Generate a keypair for the named algorithm. If `seed` is
    /// provided, it is used deterministically; otherwise the plugin
    /// generates fresh randomness.
    fn keypair_generate(
        algorithm: &str,
        seed: Option<&[u8]>,
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<SignatureKeypair>;
}
