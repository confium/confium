extern crate libc;
use libc::c_char;

#[no_mangle]
pub extern "C" fn cfm_plugin_name() -> *const c_char {
    b"hash-botan\0".as_ptr() as *const c_char
}
