//! Integration test that loads the macro-built mock plugin through the
//! standard Confium plugin loader.
//!
//! This is the proof-of-concept end-to-end test for the plugin SDK
//! proc-macros: it confirms that the FFI symbols emitted by
//! `#[plugin_interface]` and `#[export]` are wire-compatible with what
//! `cfm_plugin_load` expects.
//!
//! The mock plugin is built as a cdylib in the same workspace. Cargo
//! exposes its path via the `CARGO_CDYLIB_FILE_confium_mock_plugin`
//! environment variable, which is set when this crate is listed as a
//! dev-dependency of itself via the `[[test]]` target. Because the
//! crate exports both a cdylib and an rlib, cargo arranges the env var
//! automatically.

#![allow(clippy::implied_bounds_in_impls, clippy::missing_safety_doc)]
#![allow(non_snake_case)]
// The `cfm_plugin_load` extern declaration references Rust types
// (`Confium`, `Options`, `Error`) that aren't `#[repr(C)]`. This is
// sound because the test, the loader, and the plugin are all the same
// process binary — the raw pointers are process-local handles, never
// crossing a real ABI boundary. The lint is conservative.
#![allow(improper_ctypes)]

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use confium::Confium;
use confium::error::Error;
use confium::hash::Hash;
use confium::options::Options;

/// Path to the macro-built mock plugin's compiled cdylib. Set by the
/// build script in `confium-test-harness/build.rs` (which computes the
/// expected path from the target dir and platform file naming).
const MOCK_PLUGIN_PATH: &str = env!("CONFIUM_MOCK_PLUGIN_PATH");

unsafe extern "C" {
    fn cfm_plugin_load(
        cfm: *mut Confium,
        name: *const c_char,
        path: *const c_char,
        opts: *mut Options,
        errptr: *mut *mut Error,
    ) -> u32;
}

#[test]
fn mock_plugin_loads_and_hashes() {
    // The audit logger is disabled in tests so the JSON sink doesn't
    // touch the filesystem. The plugin load path itself does not depend
    // on audit logging.
    let mut cfm = Confium::new_with_audit(confium::audit::AuditLogger::disabled());
    let cname = CString::new("mock-hash").unwrap();
    let cpath = CString::new(MOCK_PLUGIN_PATH).unwrap();
    // The loader expects a non-NULL opts pointer (the underlying
    // `cfm_plugin_load_` does `&mut *opts` without null-checking). Pass
    // an empty Options HashMap — the mock plugin doesn't read opts.
    let mut opts = Options::new();
    let code = unsafe {
        cfm_plugin_load(
            &mut cfm,
            cname.as_ptr(),
            cpath.as_ptr(),
            &mut opts,
            ptr::null_mut(),
        )
    };
    assert_eq!(
        code, 0,
        "cfm_plugin_load returned non-zero code — plugin failed to load"
    );

    // The plugin should be loaded; now drive a hash through the
    // high-level Rust API. The mock-hash provider implements the
    // XOR-fold hash: one byte of output per input concatenated by XOR.
    let mut h = Hash::new(&cfm, "xor", Some("mock-hash"), None)
        .expect("hash construction succeeds after plugin load");
    h.update(b"hello").expect("update succeeds");
    let digest = h.finalize().expect("finalize succeeds");
    assert_eq!(digest.len(), 1, "XOR hash output is one byte");
    let expected: u8 = b'h' ^ b'e' ^ b'l' ^ b'l' ^ b'o';
    assert_eq!(digest[0], expected, "XOR-fold matches expected byte");
}

#[test]
fn mock_plugin_advertises_hash_interface() {
    // The `cfmp_query_interfaces` symbol should report `hash\0\x00\0`
    // (hash interface, version 0).
    let lib = unsafe { libloading::Library::new(MOCK_PLUGIN_PATH) }.expect("plugin dlopens");
    let query: libloading::Symbol<extern "C" fn(*const std::ffi::c_void) -> *const u8> =
        unsafe { lib.get(b"cfmp_query_interfaces\0") }.expect("symbol resolves");
    let ptr = query(std::ptr::null());
    assert!(!ptr.is_null(), "query_interfaces returned non-NULL");

    // Parse the packed `name + NUL + version_byte + NUL + ... + NUL` stream.
    let mut idx = 0;
    let mut found = false;
    loop {
        let start = idx;
        let mut end = start;
        while unsafe { *ptr.add(end) } != 0 {
            end += 1;
        }
        if end == start {
            break; // empty name terminates
        }
        let name_bytes = unsafe { std::slice::from_raw_parts(ptr.add(start), end - start) };
        let name = std::str::from_utf8(name_bytes).unwrap();
        let version = unsafe { *ptr.add(end + 1) };
        if name == "hash" && version == 0 {
            found = true;
        }
        idx = end + 2;
    }
    assert!(found, "plugin advertises hash v0");
}

#[test]
fn mock_plugin_exports_metadata() {
    let lib = unsafe { libloading::Library::new(MOCK_PLUGIN_PATH) }.expect("plugin dlopens");
    let metadata_fn: libloading::Symbol<extern "C" fn() -> *const confium_api::PluginMetadata> =
        unsafe { lib.get(b"cfmp_metadata\0") }.expect("metadata symbol resolves");
    let raw = metadata_fn();
    assert!(!raw.is_null(), "metadata returns non-NULL pointer");
    let md = unsafe { &*raw };
    unsafe {
        use std::ffi::CStr;
        assert_eq!(
            CStr::from_ptr(md.name).to_str().unwrap(),
            "confium-mock-plugin"
        );
        assert_eq!(CStr::from_ptr(md.version).to_str().unwrap(), "0.1.0");
        assert_eq!(CStr::from_ptr(md.vendor).to_str().unwrap(), "confium");
        assert_eq!(CStr::from_ptr(md.license).to_str().unwrap(), "BSD-2-Clause");
    }
}
