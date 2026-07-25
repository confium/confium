use std::ffi::CString;
use std::os::raw::c_char;

use snafu::ErrorCompat;

use crate::error::{Error, ErrorCode};

macro_rules! err_check_not_null {
    ($param:ident) => {{
        if $param.is_null() {
            let err = $crate::error::NullPointerSnafu {
                param: stringify!($param),
            }
            .build();
            eprintln!("Error: {:?}", err);
            return err.code().into();
        }
    }};
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub extern "C" fn cfm_err_get_code(err: *const Error, code: *mut u32) -> u32 {
    unsafe {
        *code = (*err).code();
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_err_get_source(err: *const Error, src: *mut *mut Error) -> u32 {
    err_check_not_null!(err);
    err_check_not_null!(src);
    unsafe { *src = std::ptr::null_mut() };
    // Walk one step down the std::error::Error chain. snafu implements
    // std::error::Error for our enum, so source() returns the wrapped
    // underlying error for variants that carry one (InvalidUTF8,
    // PluginLoadFailed, PluginSymbolError). The boxed Wrap holds the
    // Display string so the caller can read the message via the same
    // cfm_err_get_msg API.
    let Some(source) = std::error::Error::source(unsafe { &*err }) else {
        return 0;
    };
    let wrapped = crate::error::WrappedSnafu {
        message: source.to_string(),
    }
    .build();
    unsafe { *src = Box::into_raw(Box::new(wrapped)) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_err_get_backtrace(err: *mut Error, backtrace: *mut *const c_char) -> u32 {
    err_check_not_null!(err);
    err_check_not_null!(backtrace);
    unsafe { *backtrace = std::ptr::null_mut() }
    if let Some(bt) = unsafe { ErrorCompat::backtrace(&*err) } {
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

#[unsafe(no_mangle)]
pub extern "C" fn cfm_err_destroy(err: *mut Error) {
    unsafe {
        std::mem::drop(Box::from_raw(err));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use snafu::ResultExt;

    #[test]
    fn cfm_err_get_source_returns_null_when_no_source() {
        // NullPointer has no source field — the FFI call must return
        // 0 (success) and leave *src untouched (NULL).
        let err = Box::into_raw(Box::new(
            crate::error::NullPointerSnafu { param: "x" }.build(),
        ));
        let mut src: *mut Error = std::ptr::null_mut();
        let code = cfm_err_get_source(err, &mut src);
        assert_eq!(code, 0);
        assert!(src.is_null());
        cfm_err_destroy(err);
    }

    #[test]
    fn cfm_err_get_source_wraps_chained_source() {
        // InvalidUTF8 carries a Utf8Error as source. The FFI call must
        // produce a non-NULL wrapped Error whose Display string matches
        // the original Utf8Error.
        let n: u8 = 0xFF;
        let bad = [n, n];
        let utf8_err = std::str::from_utf8(&bad).unwrap_err();
        let parent: Error = Err::<(), _>(utf8_err)
            .context(crate::error::InvalidUTF8Snafu {})
            .unwrap_err();
        let parent = Box::into_raw(Box::new(parent));

        let mut src: *mut Error = std::ptr::null_mut();
        let code = cfm_err_get_source(parent, &mut src);
        assert_eq!(code, 0);
        assert!(!src.is_null());

        // Read the wrapped source's message via the same FFI API.
        let mut msg: *mut c_char = std::ptr::null_mut();
        cfm_err_get_msg(src, &mut msg);
        let msg_str = unsafe { std::ffi::CStr::from_ptr(msg).to_str().unwrap() };
        assert!(
            msg_str.contains("invalid utf-8"),
            "wrapped message should mention 'invalid utf-8', got: {msg_str}"
        );

        // Clean up both errors and the allocated string.
        cfm_err_destroy(parent);
        cfm_err_destroy(src);
        unsafe {
            std::mem::drop(Box::from_raw(msg));
        }
    }
}
