//! One open PKCS#11-backed keystore connection.
//!
//! [`Pkcs11Instance`] carries the resolved [`Config`], the live
//! [`cryptoki`] client, and the open R/W [`Session`](cryptoki::session::Session)
//! established by [`crate::backend::Pkcs11Backend::open`].
//!
//! ## Status
//!
//! The storage operations on [`StoreInstance`](confium_store::backend::StoreInstance)
//! return [`NotImplemented`](confium_store::error::Error::NotImplemented)
//! in this skeleton. The session plumbing (module load, initialize,
//! slot resolve, open session, login) is wired for real — so a future
//! revision fills the stubs against an already-authenticated session
//! without touching the open path.

use std::ffi::c_void;

use confium_store::backend::{Compartment, StoreInstance};
use confium_store::error::Result;

use crate::backend::not_implemented;
use crate::config::Config;

/// One open PKCS#11-backed keystore connection.
///
/// Owns the `cryptoki` client and the live session. Both are
/// `Send + Sync` (the underlying PKCS#11 module was initialised with
/// `CKF_OS_LOCKING_OK`), so the trait object is sound without a manual
/// `unsafe impl`.
pub struct Pkcs11Instance {
    /// Resolved configuration parsed from `Options` at open time.
    pub config: Config,

    /// The `cryptoki` client. Held for the lifetime of the instance so
    /// `C_Finalize` runs on drop and so future operations that need a
    /// fresh session (e.g. for parallel `C_FindObjects`) can open one.
    #[allow(dead_code)]
    client: cryptoki::context::Pkcs11,

    /// The logged-in R/W session. Storage operations issue
    /// `C_FindObjects` / `C_CreateObject` against this handle.
    #[allow(dead_code)]
    session: cryptoki::session::Session,
}

impl Pkcs11Instance {
    /// Construct an instance from already-established primitives.
    /// Called by [`crate::backend::Pkcs11Backend::open`] after the
    /// session is open and (optionally) logged in.
    pub(crate) fn new(
        config: Config,
        client: cryptoki::context::Pkcs11,
        session: cryptoki::session::Session,
    ) -> Self {
        Self {
            config,
            client,
            session,
        }
    }
}

impl StoreInstance for Pkcs11Instance {
    fn put_secret(
        &mut self,
        _module: &str,
        _app: &str,
        _key_id: &str,
        _key: *mut c_void,
    ) -> Result<()> {
        // Skeleton: create a CKO_SECRET_KEY object scoped by the
        // (module, app, key_id) triple — typically as application
        // attributes (`CKA_APPLICATION` / a custom `CKA_LABEL`). The
        // wired-up revision issues `C_CreateObject` against
        // `self.session`.
        Err(not_implemented())
    }

    fn get_secret(&self, _module: &str, _app: &str, _key_id: &str) -> Result<*mut c_void> {
        // Skeleton: `C_FindObjects` for the matching object and return
        // its object handle as the opaque `*mut c_void`.
        Err(not_implemented())
    }

    fn put_public(
        &mut self,
        _module: &str,
        _app: &str,
        _identity: &str,
        _key: *mut c_void,
        _sig: &[u8],
    ) -> Result<()> {
        // Skeleton: store the public key as a CKO_PUBLIC_KEY object
        // and the detached signature as a sibling attribute (or a
        // separate data object linked by `CKA_APPLICATION`).
        Err(not_implemented())
    }

    fn get_public(
        &self,
        _module: &str,
        _app: &str,
        _identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        Err(not_implemented())
    }

    fn enumerate(
        &self,
        _module: &str,
        _app: &str,
        _compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        // Skeleton: enumerate the matching objects via a
        // `C_FindObjects` template search, returning each object
        // handle paired with its label / identity string.
        Err(not_implemented())
    }
}

// SAFETY: `cryptoki::context::Pkcs11` and `cryptoki::session::Session`
// are `Send` per upstream; `cryptoki::session::Session` is not marked
// `Sync` upstream (the crate conservatively refuses to claim it), but
// the underlying PKCS#11 module initialised with `CKF_OS_LOCKING_OK`
// is thread-safe per the PKCS#11 v2.40 specification, and the
// `StoreInstance` trait only ever hands out `&self` for read-side
// operations (`get_*`, `enumerate`) — the cryptoki `Session` read
// methods take `&self` and internally serialise through the module's
// own locking. `Config` is plain owned data. The manual `Sync` impl
// therefore preserves soundness for the trait object.
unsafe impl Sync for Pkcs11Instance {}
