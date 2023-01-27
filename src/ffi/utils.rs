use crate::error::Error;
use crate::Result;
use snafu::ResultExt;
use std::os::raw::c_char;

#[macro_use]
use crate::utils;

#[macro_escape]
macro_rules! ffi_return_err {
    ($error:ident, $errptr:ident) => {{
        let code = $error.code();
        if !$errptr.is_null() {
            unsafe {
                *$errptr = Box::into_raw(Box::new($error));
            }
        }
        return code;
    }};
}

#[macro_escape]
macro_rules! ffi_check_not_null {
    ($param:ident, $errptr:ident) => {{
        if $param.is_null() {
            let err = $crate::error::NullPointer {
                param: stringify!($param),
            }
            .build();
            ffi_return_err!(err, $errptr);
        }
    }};
}

pub(crate) fn cstring(cstr: *const c_char) -> Result<String> {
    check_not_null!(cstr);
    unsafe {
        Ok(std::ffi::CStr::from_ptr(cstr)
            .to_str()
            .context(crate::error::InvalidUTF8 {})?
            .to_string())
    }
}

pub extern "C" fn cfm_string_destroy(s: *mut c_char) -> u32 {
    unsafe {
        Box::from_raw(s);
    }
    0
}
