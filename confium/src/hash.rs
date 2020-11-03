use crate::error::Error;

use libc::c_char;
use std::ffi::CStr;

pub struct Hash {}

impl Hash {
    fn new() -> Hash {
        Hash {}
    }
}

impl Drop for Hash {
    fn drop(&mut self) {}
}

pub type HashCreateFn = extern "C" fn(*const c_char, *mut *mut Hash) -> u32;

#[no_mangle]
pub extern "C" fn cfm_hash_create(c_name: *const c_char, obj: *mut *mut Hash) -> u32 {
    unsafe {
        *obj = Box::into_raw(Box::new(Hash::new()));
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_hash_destroy(obj: *mut Hash) -> u32 {
    unsafe {
        Box::from_raw(obj);
    }
    0
}
