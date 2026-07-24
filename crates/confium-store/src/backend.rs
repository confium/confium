//! Backend trait + compile-time registration.
//!
//! The Store is itself a Confium plugin, but the *backends* it ships
//! with are registered at compile time inside this crate. This keeps the
//! keystore's own extensibility story separate from the Engine's plugin
//! registry: the Engine loads the keystore plugin; the keystore in turn
//! dispatches to one of its registered backends.
//!
//! Adding a new in-tree backend is open/closed-compliant: create a new
//! module under `backends/`, implement [`StoreBackend`], and call
//! [`register_backend!`](crate::register_backend!). No edit to this file
//! is required.

use std::collections::HashMap;
use std::ffi::c_void;

use crate::error::Result;

/// Which compartment an operation targets.
///
/// Wire encoding (matches the FFI `compartment` parameter):
/// - `0` — public, identity-indexed, signed
/// - `1` — private, key-id-indexed, optionally hardware-backed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Compartment {
    Public,
    Private,
}

impl Compartment {
    /// Decode the wire value used by the FFI. Unknown values return
    /// [`crate::error::Error::InvalidCompartment`].
    pub fn from_wire(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Compartment::Public),
            1 => Ok(Compartment::Private),
            other => Err(crate::error::InvalidCompartmentSnafu { value: other }.build()),
        }
    }
}

/// Per-backend options. A thin alias over a `String → OptionValue` map so
/// backends can pull path/slot/pin-style configuration without depending
/// on the Engine's richer options model.
pub type Options = HashMap<String, String>;

/// A backend factory: knows how to open a connection to a keystore.
///
/// Implementations are stateless factories; per-keystore mutable state
/// lives in the [`StoreInstance`] they produce. `Send + Sync` so the
/// registry can hold a `&'static dyn StoreBackend` safely.
pub trait StoreBackend: Send + Sync {
    /// Wire name advertised to the FFI caller, e.g. `"memory"`,
    /// `"filesystem"`. ASCII, case-sensitive.
    fn name(&self) -> &'static str;

    /// Open the backend and return a per-keystore instance handle.
    fn open(&self, opts: &Options) -> Result<Box<dyn StoreInstance>>;
}

/// One open keystore connection. All mutation flows through `&mut self`;
/// reads take `&self` so concurrent get/enumerate is sound when the
/// underlying backend allows it.
///
/// Key material is opaque to the Store: it carries the key as a
/// `*mut c_void` (the same handle the Engine's `keyfmt` interface
/// produces). Ownership of that handle stays with the caller that
/// produced it — backends store the raw pointer and return it verbatim
/// on get. Lifetime discipline is the caller's responsibility, matching
/// the rest of the Confium FFI.
pub trait StoreInstance: Send + Sync {
    /// Insert a secret key into the private compartment, indexed by
    /// `key_id`.
    fn put_secret(
        &mut self,
        module: &str,
        app: &str,
        key_id: &str,
        key: *mut c_void,
    ) -> Result<()>;

    /// Fetch a secret key from the private compartment by `key_id`.
    /// Returns [`crate::error::Error::ValueNotFound`] if absent.
    fn get_secret(&self, module: &str, app: &str, key_id: &str) -> Result<*mut c_void>;

    /// Insert a public key into the public compartment, indexed by
    /// `identity`, with a detached signature over the identity.
    fn put_public(
        &mut self,
        module: &str,
        app: &str,
        identity: &str,
        key: *mut c_void,
        sig: &[u8],
    ) -> Result<()>;

    /// Fetch a public key from the public compartment by `identity`.
    /// Returns the key handle and the stored signature bytes.
    fn get_public(&self, module: &str, app: &str, identity: &str)
        -> Result<(*mut c_void, Vec<u8>)>;

    /// Enumerate entries in one compartment of one `(module, app)`
    /// scope. Each entry is the opaque key handle paired with its index
    /// string (`key_id` for private, canonical identity for public).
    fn enumerate(
        &self,
        module: &str,
        app: &str,
        compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>>;
}

// --- link-time registry --------------------------------------------------

/// Wrapper around `&'static dyn StoreBackend` so a backend can be
/// registered with `inventory` and discovered at link time.
pub struct RegisteredBackend {
    pub backend: &'static dyn StoreBackend,
}

inventory::collect!(RegisteredBackend);

/// Iterate every backend registered at link time.
pub fn iter() -> impl Iterator<Item = &'static dyn StoreBackend> {
    inventory::iter::<RegisteredBackend>().map(|r| r.backend)
}

/// Look up a backend by wire name. Returns
/// [`crate::error::Error::UnknownBackend`] if no registered backend
/// matches.
pub fn find(name: &str) -> Result<&'static dyn StoreBackend> {
    iter()
        .find(|b| b.name() == name)
        .ok_or_else(|| crate::error::UnknownBackendSnafu { name }.build())
}

/// Submit a backend to the link-time registry.
///
/// ```no_run
/// # use confium_store::backend::{StoreBackend, StoreInstance, Options};
/// # use confium_store::error::Result;
/// # use std::ffi::c_void;
/// # struct MyBackend;
/// # impl StoreBackend for MyBackend {
/// #     fn name(&self) -> &'static str { "mine" }
/// #     fn open(&self, _: &Options) -> Result<Box<dyn StoreInstance>> { unimplemented!() }
/// # }
/// confium_store::register_backend!(MyBackend);
/// ```
#[macro_export]
macro_rules! register_backend {
    ($backend:ident) => {
        ::inventory::submit! {
            $crate::backend::RegisteredBackend { backend: &$backend }
        }
    };
}
