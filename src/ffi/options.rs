use std::ffi::CString;
use std::os::raw::c_char;

use crate::error;
use crate::error::Error;
use crate::ffi::utils::cstring;
use crate::options::{OptionValue, Options};

#[no_mangle]
pub extern "C" fn cfm_opts_create(opts: *mut *mut Options, err: *mut *mut Error) -> u32 {
    ffi_check_not_null!(opts, err);
    unsafe {
        *opts = Box::into_raw(Box::new(Options::new()));
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_opts_destroy(opts: *mut Options) -> u32 {
    if !opts.is_null() {
        unsafe {
            std::mem::drop(Box::from_raw(opts));
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_opts_set_u32(
    opts: *mut Options,
    key: *const c_char,
    value: u32,
    err: *mut *mut Error,
) -> u32 {
    ffi_check_not_null!(opts, err);
    ffi_check_not_null!(key, err);
    let key = match cstring(key) {
        Ok(s) => s,
        Err(e) => {
            ffi_return_err!(e, err);
        }
    };
    unsafe {
        (*opts).insert(key, OptionValue::U32(value));
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_opts_get_u32(
    opts: *mut Options,
    key: *const c_char,
    value: *mut u32,
    err: *mut *mut Error,
) -> u32 {
    ffi_check_not_null!(opts, err);
    ffi_check_not_null!(key, err);
    ffi_check_not_null!(value, err);
    let key = match cstring(key) {
        Ok(s) => s,
        Err(e) => {
            ffi_return_err!(e, err);
        }
    };
    unsafe {
        if let Some(v) = (*opts).get(&key) {
            if let OptionValue::U32(v) = v {
                *value = *v;
            } else {
                let e = error::WrongType { expected: "u32" }.build();
                ffi_return_err!(e, err);
            }
        } else {
            let e = error::ValueNotFound.build();
            ffi_return_err!(e, err);
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_opts_set_string(
    opts: *mut Options,
    key: *const c_char,
    value: *const c_char,
    err: *mut *mut Error,
) -> u32 {
    ffi_check_not_null!(opts, err);
    ffi_check_not_null!(key, err);
    ffi_check_not_null!(value, err);
    let key = match cstring(key) {
        Ok(s) => s,
        Err(e) => {
            ffi_return_err!(e, err);
        }
    };
    let value = match cstring(value) {
        Ok(s) => s,
        Err(e) => {
            ffi_return_err!(e, err);
        }
    };
    unsafe {
        (*opts).insert(key, OptionValue::String(value));
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_opts_get_string(
    opts: *mut Options,
    key: *const c_char,
    value: *mut *const c_char,
    err: *mut *mut Error,
) -> u32 {
    ffi_check_not_null!(opts, err);
    ffi_check_not_null!(key, err);
    ffi_check_not_null!(value, err);
    let key = match cstring(key) {
        Ok(s) => s,
        Err(e) => {
            ffi_return_err!(e, err);
        }
    };
    unsafe {
        if let Some(ref v) = (*opts).get(&key) {
            if let OptionValue::String(ref s) = v {
                *value = CString::new(s.clone()).unwrap().into_raw();
            } else {
                let e = error::WrongType { expected: "string" }.build();
                ffi_return_err!(e, err);
            }
        } else {
            let e = error::ValueNotFound.build();
            ffi_return_err!(e, err);
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_opts_remove(
    opts: *mut Options,
    key: *const c_char,
    err: *mut *mut Error,
) -> u32 {
    ffi_check_not_null!(opts, err);
    ffi_check_not_null!(key, err);
    let key = match cstring(key) {
        Ok(s) => s,
        Err(e) => {
            ffi_return_err!(e, err);
        }
    };
    unsafe {
        (*opts).remove(&key);
    }
    0
}
#[no_mangle]
pub extern "C" fn cfm_opts_clear(opts: *mut Options, err: *mut *mut Error) -> u32 {
    ffi_check_not_null!(opts, err);
    unsafe {
        (*opts).clear();
    }
    0
}
