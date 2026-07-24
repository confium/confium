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

use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use libloading::Library;

use error::Error;

use ffi::plugin::PluginInterface;
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
    pub interfaces: Vec<Rc<PluginInterface>>,
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
