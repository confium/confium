use std::ffi::CString;
use std::os::raw::c_char;

use crate::error::Error;
use crate::Confium;

#[no_mangle]
pub extern "C" fn cfm_create(cfm: *mut *mut Confium) -> u32 {
    unsafe { *cfm = Box::into_raw(Box::new(Confium::new())) }
    0
}

#[no_mangle]
pub extern "C" fn cfm_destroy(cfm: *mut Confium) -> u32 {
    unsafe {
        Box::from_raw(cfm);
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_version_string(version: *mut *mut c_char) -> u32 {
    let vers = CString::new(crate::VERSION).unwrap();
    unsafe {
        *version = vers.into_raw();
    }
    0
}

fn cfm_version_component(n: usize) -> u32 {
    crate::VERSION
        .split('.')
        .nth(n)
        .unwrap()
        .parse::<u32>()
        .unwrap()
}

// these may panic if the library version is incorrectly
// formatted
#[no_mangle]
pub extern "C" fn cfm_version_major() -> u32 {
    cfm_version_component(0)
}

#[no_mangle]
pub extern "C" fn cfm_version_minor() -> u32 {
    cfm_version_component(1)
}

#[no_mangle]
pub extern "C" fn cfm_version_patch() -> u32 {
    cfm_version_component(2)
}
