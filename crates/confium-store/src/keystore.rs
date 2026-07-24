//! Public-facing [`Keystore`] wrapper.
//!
//! A `Keystore` owns a [`crate::backend::StoreInstance`] produced by a
//! registered backend. It is the Rust-side handle the FFI layer boxes
//! into the opaque `FFIKeystore` pointer.
//!
//! The wrapper exists to keep backend dispatch centralised: the FFI
//! functions delegate here, and this module is the one place that knows
//! how to translate `(module_id, app_id)` strings into backend calls.

use std::ffi::c_void;

use crate::backend::{Compartment, Options, StoreInstance, find};
use crate::error::Result;

/// An open keystore connection.
///
/// Construct one with [`Keystore::new`] by naming a registered backend.
/// The backend's instance is held behind a `Box<dyn StoreInstance>` so
/// the public API is backend-agnostic.
pub struct Keystore {
    instance: Box<dyn StoreInstance>,
}

impl Keystore {
    /// Open a keystore backed by `backend_name`. The caller may supply
    /// backend-specific options (path, slot, pin, …).
    pub fn new(backend_name: &str, opts: &Options) -> Result<Self> {
        let backend = find(backend_name)?;
        let instance = backend.open(opts)?;
        Ok(Keystore { instance })
    }

    /// Wrap an already-constructed instance. Used by tests and by FFI
    /// paths that have already resolved the backend.
    pub fn from_instance(instance: Box<dyn StoreInstance>) -> Self {
        Keystore { instance }
    }

    /// Borrow the underlying instance mutably. The FFI layer uses this
    /// to dispatch `put_*` calls.
    pub fn instance_mut(&mut self) -> &mut dyn StoreInstance {
        self.instance.as_mut()
    }

    /// Borrow the underlying instance. The FFI layer uses this to
    /// dispatch `get_*` / `enumerate` calls.
    pub fn instance(&self) -> &dyn StoreInstance {
        self.instance.as_ref()
    }

    pub fn put_secret(
        &mut self,
        module: &str,
        app: &str,
        key_id: &str,
        key: *mut c_void,
    ) -> Result<()> {
        self.instance.put_secret(module, app, key_id, key)
    }

    pub fn get_secret(&self, module: &str, app: &str, key_id: &str) -> Result<*mut c_void> {
        self.instance.get_secret(module, app, key_id)
    }

    pub fn put_public(
        &mut self,
        module: &str,
        app: &str,
        identity: &str,
        key: *mut c_void,
        sig: &[u8],
    ) -> Result<()> {
        self.instance.put_public(module, app, identity, key, sig)
    }

    pub fn get_public(
        &self,
        module: &str,
        app: &str,
        identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        self.instance.get_public(module, app, identity)
    }

    pub fn enumerate(
        &self,
        module: &str,
        app: &str,
        compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        self.instance.enumerate(module, app, compartment)
    }
}
