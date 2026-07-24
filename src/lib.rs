// FFI entry points accept raw pointers and null-check them before
// dereferencing; they are not `unsafe` from the C caller's perspective.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

#[macro_use]
pub mod utils;
pub mod error;
#[macro_use]
pub mod ffi;
pub mod hash;
pub mod options;
pub mod rng;
pub mod sensitive;

use std::any::Any;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use libloading::Library;

use error::Error;

use ffi::plugin::PluginVTable;

type StringOptions = HashMap<String, String>;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type Result<T> = std::result::Result<T, Error>;

pub struct Provider {
    pub name: String,
    pub plugin: Plugin,
}

pub struct Plugin {
    pub library: Rc<Library>,
    pub vtable: PluginVTable,
    /// Each interface advertised by the plugin, type-erased so the core
    /// doesn't need a closed enum of interface variants. Concrete
    /// interface types live in their respective modules (`ffi::hash`,
    /// `ffi::cipher`, etc.).
    pub interfaces: Vec<PluginInterface>,
}

/// A type-erased plugin interface with its negotiated name and version.
///
/// Concrete interface types are recovered via downcast by the consumer
/// module that owns the type (e.g. `hash::interface_for(plugin)`).
pub struct PluginInterface {
    pub name: &'static str,
    pub version: u8,
    pub inner: Rc<dyn Any>,
}

impl PluginInterface {
    /// Borrow the underlying concrete interface if it matches `T`.
    pub fn downcast<T: Any>(&self) -> Option<&T> {
        self.inner.downcast_ref::<T>()
    }

    /// Clone a shared handle to the underlying concrete interface if it
    /// matches `T`.
    pub fn clone_inner<T: Any>(&self) -> Option<Rc<T>> {
        Rc::clone(&self.inner).downcast::<T>().ok()
    }
}

pub struct Confium {
    providers: Vec<Provider>,
    preferred_providers: HashMap<String, Vec<String>>,
}

impl Confium {
    pub fn new() -> Self {
        Confium {
            providers: Vec::new(),
            preferred_providers: HashMap::new(),
        }
    }

    // TODO: Support Rust plugins
    pub fn load_plugin(&self, _path: &Path, _options: &StringOptions) -> Result<()> {
        unimplemented!();
    }
}

impl Default for Confium {
    fn default() -> Self {
        Self::new()
    }
}
