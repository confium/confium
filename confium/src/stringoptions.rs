use libc::c_char;
use std::collections::HashMap;

type StringOptions = HashMap<String, String>;

#[no_mangle]
pub extern "C" fn cfm_sopts_create(obj: *mut *mut StringOptions) -> u32 {
    unsafe {
        *obj = Box::into_raw(Box::new(StringOptions::new()));
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_sopts_destroy(obj: *mut StringOptions) -> u32 {
    unsafe {
        Box::from_raw(obj);
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_sopts_clear(obj: *mut StringOptions) -> u32 {
    unsafe {
        (*obj).clear();
    }
    0
}
