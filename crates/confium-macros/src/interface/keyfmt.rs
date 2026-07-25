//! Wire protocol generator for the key serialization (keyfmt)
//! interface (v0).
//!
//! Emits the six `cfmp_keyfmt_*` symbols from an
//! `impl KeyfmtPlugin for T` block.
//!
//! The parse entry point has a complex parameter list fixed by the C
//! ABI; the macro emits `#[allow(clippy::too_many_arguments)]`
//! automatically.

use proc_macro2::TokenStream;
use quote::quote;

/// Emit the keyfmt v0 FFI symbols for the given implementing type.
pub fn generate_v0(self_ty: &syn::Type) -> syn::Result<TokenStream> {
    let _ = self_ty;

    Ok(quote! {
        // ---- cfmp_keyfmt_parse ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_keyfmt_parse(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            format: *const std::os::raw::c_char,
            algorithm_hint: *const std::os::raw::c_char,
            bytes: *const u8,
            len: u32,
            opts: *const std::ffi::c_void,
        ) -> u32 {
            use std::ffi::CStr;
            let out = match out.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            if format.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let format = match CStr::from_ptr(format).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return ::confium_api::ErrorCode::INVALID_UTF8.into_wire(),
            };
            let algorithm_hint = if algorithm_hint.is_null() {
                None
            } else {
                match CStr::from_ptr(algorithm_hint).to_str() {
                    Ok(s) => Some(s.to_string()),
                    Err(_) => return ::confium_api::ErrorCode::INVALID_UTF8.into_wire(),
                }
            };
            let algorithm_hint = algorithm_hint.as_deref();
            let bytes: &[u8] = if bytes.is_null() || len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(bytes, len as usize) }
            };
            let opts_view = if opts.is_null() {
                None
            } else {
                unsafe { ::confium_api::OptionView::from_raw_ptr(opts) }
            };
            <#self_ty as ::confium_api::plugin::keyfmt::KeyfmtPlugin>::parse(
                &format, algorithm_hint, bytes, opts_view,
            )
            .map(|inst| { *out = ::confium_api::OpaqueHandle::new(inst); })
            .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_keyfmt_serialize ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_keyfmt_serialize(
            handle: *const std::ffi::c_void,
            format: *const std::os::raw::c_char,
            out: *mut u8,
            out_max: u32,
            out_len: *mut u32,
        ) -> u32 {
            if handle.is_null() || format.is_null() || out_len.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            use std::ffi::CStr;
            let format = match CStr::from_ptr(format).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return ::confium_api::ErrorCode::INVALID_UTF8.into_wire(),
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle as *mut _);
            match <#self_ty as ::confium_api::plugin::keyfmt::KeyfmtPlugin>::serialize(&inst, &format) {
                Ok(bytes) => {
                    let n = bytes.len();
                    if n > out_max as usize {
                        return ::confium_api::ErrorCode::INSUFFICIENT_BUFFER.into_wire();
                    }
                    if !out.is_null() && n > 0 {
                        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, n); }
                    }
                    unsafe { *out_len = n as u32; }
                    0
                }
                Err(e) => e.into_wire(),
            }
        }

        // ---- cfmp_keyfmt_kind ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_keyfmt_kind(
            handle: *const std::ffi::c_void,
            out_kind: *mut u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let out_kind = match out_kind.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle as *mut _);
            match <#self_ty as ::confium_api::plugin::keyfmt::KeyfmtPlugin>::kind(&inst) {
                Ok(kind) => {
                    *out_kind = kind as u32;
                    0
                }
                Err(e) => e.into_wire(),
            }
        }

        // ---- cfmp_keyfmt_algorithm ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_keyfmt_algorithm(
            handle: *const std::ffi::c_void,
            algorithm_out: *mut *mut std::os::raw::c_char,
        ) -> u32 {
            if handle.is_null() || algorithm_out.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle as *mut _);
            match <#self_ty as ::confium_api::plugin::keyfmt::KeyfmtPlugin>::algorithm(&inst) {
                Ok(algorithm) => {
                    // Algorithm names never contain interior NULs; if
                    // they do, that's a plugin contract breach.
                    match std::ffi::CString::new(algorithm) {
                        Ok(cstr) => {
                            unsafe { *algorithm_out = cstr.into_raw(); }
                            0
                        }
                        Err(_) => ::confium_api::ErrorCode::PLUGIN_GENERIC.into_wire(),
                    }
                }
                Err(e) => e.into_wire(),
            }
        }

        // ---- cfmp_keyfmt_public ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_keyfmt_public(
            handle: *const std::ffi::c_void,
            public_only_out: *mut *mut std::ffi::c_void,
        ) -> u32 {
            if handle.is_null() || public_only_out.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle as *mut _);
            match <#self_ty as ::confium_api::plugin::keyfmt::KeyfmtPlugin>::public(&inst) {
                Ok(public) => {
                    unsafe { *public_only_out = ::confium_api::OpaqueHandle::new(public); }
                    0
                }
                Err(e) => e.into_wire(),
            }
        }

        // ---- cfmp_keyfmt_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_keyfmt_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }
    })
}
