//! `KemPlugin` trait — the Rust-side counterpart of the KEM v0 wire
//! protocol.
//!
//! The KEM interface has two object types: an encapsulator (sender,
//! holds the recipient's public key) and a decapsulator (recipient,
//! holds the recipient's secret key). A single plugin implements both,
//! plus keypair generation and a shared-secret size query.
//!
//! Plugin authors implement this trait on a state type, then apply
//! `#[plugin_interface(name = "kem", version = 0)]` to the impl block.
//!
//! See `crates/confium-core/src/ffi/kem.rs` for the loader-side wire
//! types.

use crate::error::PluginResult;
use crate::options::OptionView;

/// Result of encapsulation: the ciphertext to send and the shared
/// secret.
pub struct KemEncapsulateResult {
    /// Ciphertext bytes to send to the recipient.
    pub ciphertext: Vec<u8>,
    /// Shared secret derived on the sender side.
    pub shared_secret: Vec<u8>,
}

/// Result of keypair generation.
pub struct KemKeypair {
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Secret key bytes.
    pub secret_key: Vec<u8>,
}

/// Trait implemented by KEM plugins. The type `Self` serves as both the
/// encapsulator and decapsulator state — the plugin dispatches
/// internally based on which entry points are called.
pub trait KemPlugin: Sized {
    /// Construct an encapsulator from the recipient's public key.
    fn encapsulator_create(
        algorithm: &str,
        recipient_pubkey: &[u8],
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<Self>;

    /// Encapsulate: produce a ciphertext and shared secret. Writes the
    /// ciphertext and shared secret into the provided output buffers
    /// and returns their lengths.
    fn encapsulate(
        &mut self,
        ct_out: &mut [u8],
        ss_out: &mut [u8],
    ) -> PluginResult<KemEncapsulateResult>;

    /// Construct a decapsulator from the recipient's secret key.
    fn decapsulator_create(
        algorithm: &str,
        recipient_seckey: &[u8],
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<Self>;

    /// Decapsulate: recover the shared secret from the ciphertext.
    /// Writes the shared secret into `ss_out` and returns its length.
    fn decapsulate(&mut self, ciphertext: &[u8], ss_out: &mut [u8]) -> PluginResult<usize>;

    /// Query the shared secret size for the named algorithm.
    fn shared_secret_size(algorithm: &str) -> PluginResult<u32>;

    /// Generate a keypair for the named algorithm. If `seed` is
    /// provided, it is used deterministically.
    fn keypair_generate(
        algorithm: &str,
        seed: Option<&[u8]>,
        opts: Option<OptionView<'_>>,
    ) -> PluginResult<KemKeypair>;
}
