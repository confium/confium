extern crate libc;
extern crate libloading;
#[macro_use]
pub extern crate slog;
extern crate slog_async;
extern crate slog_stdlog;
extern crate slog_term;

#[macro_use]
pub mod utils;
pub mod error;
pub mod hash;
pub mod stringoptions;

use libc::c_char;
use std::ffi::CStr;
use std::rc::Rc;

use libloading::Library;
use slog::Drain;

use error::Error;
use hash::Hash;

type HashCreateFn = extern "C" fn(ffi: *mut FFI, *const c_char, *mut *mut Hash) -> u32;
type HashDestroyFn = extern "C" fn(ffi: *mut FFI, *mut Hash) -> u32;

pub struct HashPlugin {
    create: HashCreateFn,
    destroy: HashDestroyFn,
}

pub struct FFI {
    libraries: Vec<Rc<Library>>,
    logger: slog::Logger,
}

impl FFI {
    pub fn new<L: Into<Option<slog::Logger>>>(logger: L) -> Self {
        FFI {
            libraries: Vec::new(),
            logger: logger
                .into()
                .unwrap_or(slog::Logger::root(slog_stdlog::StdLog.fuse(), o!())),
        }
    }
}

#[no_mangle]
pub extern "C" fn cfm_create(ffi: *mut *mut FFI) -> u32 {
    unsafe {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let log = slog::Logger::root(drain, o!("version" => "5"));
        *ffi = Box::into_raw(Box::new(FFI::new(log)));
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_destroy(ffi: *mut FFI) -> u32 {
    unsafe {
        Box::from_raw(ffi);
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_load_plugin(ffi: *mut FFI, c_path: *const c_char) -> u32 {
    if ffi.is_null() || c_path.is_null() {
        return u32::from(Error::NullPointer);
    }
    let path = cstring!(c_path);
    let lib = Rc::new(match Library::new(path) {
        Ok(l) => l,
        Err(e) => {
            unsafe {
                error!((*ffi).logger, "Failed to load plugin: {}", e);
            }
            return u32::from(Error::PluginLoadError);
        }
    });
    unsafe {
        let namefn = lib
            .get::<fn() -> *const c_char>(b"cfm_plugin_name\0")
            .unwrap();
        let name = namefn();
        println!("Plugin name: '{}'", cstring!(name));
    }
    0
}
