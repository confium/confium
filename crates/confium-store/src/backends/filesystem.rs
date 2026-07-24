//! Filesystem backend (stub).
//!
//! The real filesystem backend will store RFC 9580 keyring packets in
//! compartmentalised directories, gated by the `keyfmt` interface (TODO
//! #11). Until keyfmt lands, every operation returns
//! [`crate::error::Error::NotImplemented`] so callers get a clear,
//! typed signal rather than a silent no-op.

use std::ffi::c_void;

use crate::backend::{Compartment, Options, StoreBackend, StoreInstance};
use crate::error::{Error, NotImplementedSnafu, Result};
use crate::register_backend;

const WHAT: &str = "filesystem backend";

pub struct FilesystemBackend;

impl StoreBackend for FilesystemBackend {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn open(&self, _opts: &Options) -> Result<Box<dyn StoreInstance>> {
        Err(NotImplementedSnafu { what: WHAT }.build())
    }
}

register_backend!(FilesystemBackend);

/// Placeholder instance. `open` never succeeds, so this exists only to
/// satisfy the trait bound on `Box<dyn StoreInstance>` for future
/// implementations.
pub struct FilesystemInstance;

impl StoreInstance for FilesystemInstance {
    fn put_secret(
        &mut self,
        _module: &str,
        _app: &str,
        _key_id: &str,
        _key: *mut c_void,
    ) -> Result<()> {
        Err(Error::NotImplemented { what: WHAT })
    }

    fn get_secret(&self, _module: &str, _app: &str, _key_id: &str) -> Result<*mut c_void> {
        Err(Error::NotImplemented { what: WHAT })
    }

    fn put_public(
        &mut self,
        _module: &str,
        _app: &str,
        _identity: &str,
        _key: *mut c_void,
        _sig: &[u8],
    ) -> Result<()> {
        Err(Error::NotImplemented { what: WHAT })
    }

    fn get_public(
        &self,
        _module: &str,
        _app: &str,
        _identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        Err(Error::NotImplemented { what: WHAT })
    }

    fn enumerate(
        &self,
        _module: &str,
        _app: &str,
        _compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        Err(Error::NotImplemented { what: WHAT })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::StoreBackend;

    #[test]
    fn open_returns_not_implemented() {
        let result = FilesystemBackend.open(&Options::new());
        let err = match result {
            Ok(_) => panic!("expected NotImplemented, got Ok"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::NotImplemented { what: WHAT }));
        assert_eq!(err.code(), crate::error::ErrorCode::NOT_IMPLEMENTED as u32);
    }

    #[test]
    fn backend_is_registered() {
        // Even though it can't open yet, the backend must be in the
        // registry so the wire name resolves and the FFI surfaces a
        // typed NotImplemented rather than UnknownBackend.
        let backend = crate::backend::find("filesystem").expect("filesystem registered");
        assert_eq!(backend.name(), "filesystem");
    }
}
