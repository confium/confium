use std::ffi::CString;
use std::os::raw::c_char;

use snafu::ErrorCompat;

use crate::error::{Error, ErrorCode};

macro_rules! err_check_not_null {
    ($param:ident) => {{
        if $param.is_null() {
            let err = $crate::error::NullPointer {
                param: stringify!($param),
            }
            .build();
            eprintln!("Error: {:?}", err);
            return err.code().into();
        }
    }};
}

#[no_mangle]
pub extern "C" fn cfm_err_get_msg(err: *const Error, msg: *mut *mut c_char) -> u32 {
    err_check_not_null!(err);
    err_check_not_null!(msg);
    let errmsg;
    unsafe {
        *msg = std::ptr::null_mut();
        errmsg = format!("{}", *err);
    }
    match CString::new(errmsg) {
        Ok(s) => unsafe { *msg = s.into_raw() },
        Err(e) => {
            eprintln!("Error: {:?}", e);
            return ErrorCode::UNKNOWN as u32;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_err_get_code(err: *const Error, code: *mut u32) -> u32 {
    unsafe {
        *code = (*err).code();
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_err_get_source(err: *const Error, src: *mut *mut Error) -> u32 {
    unimplemented!();
}

#[no_mangle]
pub extern "C" fn cfm_err_get_backtrace(err: *mut Error, backtrace: *mut *const c_char) -> u32 {
    err_check_not_null!(err);
    err_check_not_null!(backtrace);
    unsafe { *backtrace = std::ptr::null_mut() }
    if let Some(ref bt) = unsafe { ErrorCompat::backtrace(&*err) } {
        match CString::new(bt.to_string()) {
            Ok(s) => unsafe { *backtrace = s.into_raw() },
            Err(e) => {
                eprintln!("Error: {}", e);
                return ErrorCode::UNKNOWN as u32;
            }
        };
    }
    0
}

#[no_mangle]
pub extern "C" fn cfm_err_destroy(err: *mut Error) {
    unsafe {
        Box::from_raw(err);
    }
}
