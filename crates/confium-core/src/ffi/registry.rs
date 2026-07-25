//! Open/closed plugin-interface registry.
//!
//! Each interface module (hash, cipher, aead, kdf, rng, signature, kem,
//! keyfmt, keystore) submits a [`PluginInterfaceKind`] implementation via
//! the [`register_interface!`] macro. The plugin loader iterates registered
//! kinds to find the one matching a plugin-advertised interface name.
//!
//! Adding a new interface type means adding a new module that calls
//! `register_interface!` — no edits to existing code.

use std::any::Any;
use std::fmt;
use std::rc::Rc;

use libloading::Library;

use crate::Result;

/// One entry in the interface registry: knows how to negotiate a version
/// with the plugin and build a type-erased interface handle.
pub trait PluginInterfaceKind: Sync {
    /// Wire name advertised via the plugin's `cfmp_query_interfaces`
    /// payload. ASCII, no NUL, e.g. `"hash"`, `"symmetric"`.
    fn name(&self) -> &'static str;

    /// Highest version this build of Confium understands. Plugins can
    /// advertise multiple versions; the loader negotiates the highest
    /// mutually supported one.
    fn max_version(&self) -> u8;

    /// Build a concrete interface object from the plugin's dynamic
    /// library, given a negotiated version. Returns `Ok(None)` if the
    /// specific version is not implemented by this Confium build.
    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>>;
}

/// Wrapper around `&'static dyn PluginInterfaceKind` so the kind can be
/// registered with `inventory` and discovered at link time.
pub struct RegisteredKind {
    pub kind: &'static dyn PluginInterfaceKind,
}

inventory::collect!(RegisteredKind);

/// Iterator over all interface kinds registered at link time.
pub fn iter() -> impl Iterator<Item = &'static dyn PluginInterfaceKind> {
    inventory::iter::<RegisteredKind>().map(|r| r.kind)
}

impl fmt::Debug for dyn PluginInterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginInterfaceKind")
            .field("name", &self.name())
            .field("max_version", &self.max_version())
            .finish()
    }
}

/// Submit an interface kind to the link-time registry.
///
/// ```no_run
/// use confium::ffi::registry::PluginInterfaceKind;
/// use confium::register_interface;
/// # use confium::Result;
/// # use std::any::Any;
/// # use std::rc::Rc;
/// # use libloading::Library;
/// # struct HashKind;
/// # impl PluginInterfaceKind for HashKind {
/// #     fn name(&self) -> &'static str { "hash" }
/// #     fn max_version(&self) -> u8 { 0 }
/// #     fn build(&self, _: &Library, _: u8) -> Result<Option<Rc<dyn Any>>> { Ok(None) }
/// # }
/// register_interface!(HashKind);
/// ```
#[macro_export]
macro_rules! register_interface {
    ($kind:ident) => {
        ::inventory::submit! {
            $crate::ffi::registry::RegisteredKind { kind: &$kind }
        }
    };
}
