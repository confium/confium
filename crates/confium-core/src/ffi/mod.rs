// FFI entry points use raw pointers throughout. The `ffi_return_err!` macro
// wraps a write through `*mut *mut Error` in an `unsafe` block so it can be
// invoked from safe contexts; that block is flagged as redundant when the
// macro happens to be expanded inside another `unsafe` block.
#![allow(unused_unsafe)]

#[macro_use]
pub mod utils;
pub mod aead;
pub mod cipher;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod keyfmt;
pub mod lib;
pub mod options;
pub mod plugin;
pub mod registry;
pub mod rng;
pub mod signature;
