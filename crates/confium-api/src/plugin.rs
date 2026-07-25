//! Traits plugin authors implement for each Confium interface.
//!
//! Each sub-module mirrors one interface's wire protocol: the trait
//! method set matches the `cfmp_<iface>_*` symbols one-for-one. The
//! `#[plugin_interface]` proc-macro dispatches on the trait to emit the
//! FFI entry points.

pub mod aead;
pub mod cipher;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod keyfmt;
pub mod rng;
pub mod signature;

pub use aead::AeadPlugin;
pub use cipher::CipherPlugin;
pub use hash::HashPlugin;
pub use kdf::KdfPlugin;
pub use kem::KemPlugin;
pub use keyfmt::KeyfmtPlugin;
pub use rng::RngPlugin;
pub use signature::SignaturePlugin;
