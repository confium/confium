//! Wire protocol generator for the symmetric cipher interface (v0).
//!
//! Emits the eight `cfmp_cipher_*` symbols from an
//! `impl CipherPlugin for T` block. The trait lives in
//! `confium_api::plugin::cipher::CipherPlugin`.
//!
//! Note: the wire name advertised via `cfmp_query_interfaces` is
//! `symmetric` (matching the loader-side `CipherKind`), not `cipher`.
//! The symbol prefix is `cfmp_cipher_`.

use proc_macro2::TokenStream;
use quote::quote;

/// Emit the cipher v0 FFI symbols for the given implementing type.
pub fn generate_v0(self_ty: &syn::Type) -> syn::Result<TokenStream> {
    let _ = self_ty;

    Ok(quote! {
        // ---- cfmp_cipher_create ----
        //
        // Wire: extern "C" fn(*const Confium, *mut *mut FFICipher,
        //                     *const c_char algorithm,
        //                     *const void key, u32 key_len,
        //                     *const void iv,  u32 iv_len,
        //                     *const OptionMap) -> u32
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_cipher_create(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
            key: *const std::ffi::c_void,
            key_len: u32,
            iv: *const std::ffi::c_void,
            iv_len: u32,
            opts: *const std::ffi::c_void,
        ) -> u32 {
            use std::ffi::CStr;
            let out = match out.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            if algorithm.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let algorithm = match CStr::from_ptr(algorithm).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return ::confium_api::ErrorCode::INVALID_UTF8.into_wire(),
            };
            let key: &[u8] = if key.is_null() || key_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(key as *const u8, key_len as usize) }
            };
            let iv: &[u8] = if iv.is_null() || iv_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(iv as *const u8, iv_len as usize) }
            };
            let opts_view = if opts.is_null() {
                None
            } else {
                // SAFETY: the loader hands us a &OptionMap borrow valid
                // for this call.
                unsafe { ::confium_api::OptionView::from_raw_ptr(opts) }
            };
            <#self_ty as ::confium_api::plugin::cipher::CipherPlugin>::create_with_key(
                &algorithm,
                key,
                iv,
                opts_view,
            )
            .map(|inst| {
                *out = ::confium_api::OpaqueHandle::new(inst);
            })
            .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_cipher_block_size ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_cipher_block_size(
            handle: *const std::ffi::c_void,
            out: *mut u32,
        ) -> u32 {
            let out = match out.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle as *mut _);
            *out = <#self_ty as ::confium_api::plugin::cipher::CipherPlugin>::block_size(&inst);
            0
        }

        // ---- cfmp_cipher_key_size ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_cipher_key_size(
            handle: *const std::ffi::c_void,
            out: *mut u32,
        ) -> u32 {
            let out = match out.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle as *mut _);
            *out = <#self_ty as ::confium_api::plugin::cipher::CipherPlugin>::key_size(&inst);
            0
        }

        // ---- cfmp_cipher_iv_size ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_cipher_iv_size(
            handle: *const std::ffi::c_void,
            out: *mut u32,
        ) -> u32 {
            let out = match out.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle as *mut _);
            *out = <#self_ty as ::confium_api::plugin::cipher::CipherPlugin>::iv_size(&inst);
            0
        }

        // ---- cfmp_cipher_update ----
        //
        // Wire: extern "C" fn(*mut FFICipher, *const u8 in, u32 in_len,
        //                     *mut u8 out, *mut u32 out_len) -> u32
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_cipher_update(
            handle: *mut std::ffi::c_void,
            input: *const u8,
            in_len: u32,
            output: *mut u8,
            out_len: *mut u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let out_len = match out_len.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            let avail = *out_len as usize;
            if output.is_null() && avail != 0 {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let input: &[u8] = if input.is_null() || in_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(input, in_len as usize) }
            };
            let output: &mut [u8] = if output.is_null() {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(output, avail) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::cipher::CipherPlugin>::update(inst, input, output)
                .map(|written| {
                    *out_len = written as u32;
                    0u32
                })
                .map_or_else(|e| e.into_wire(), |c| c)
        }

        // ---- cfmp_cipher_finalize ----
        //
        // Wire: extern "C" fn(*mut FFICipher, *mut u8 out, u32 out_max,
        //                     *mut u32 out_len) -> u32
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_cipher_finalize(
            handle: *mut std::ffi::c_void,
            output: *mut u8,
            out_max: u32,
            out_len: *mut u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let out_len = match out_len.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            let avail = out_max as usize;
            if output.is_null() && avail != 0 {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let output: &mut [u8] = if output.is_null() {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(output, avail) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::cipher::CipherPlugin>::finalize(inst, output)
                .map(|written| {
                    *out_len = written as u32;
                    0u32
                })
                .map_or_else(|e| e.into_wire(), |c| c)
        }

        // ---- cfmp_cipher_reset ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_cipher_reset(
            handle: *mut std::ffi::c_void,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::cipher::CipherPlugin>::reset(inst)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_cipher_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_cipher_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            // SAFETY: the loader invokes `destroy` exactly once per
            // pointer produced by `cfmp_cipher_create`.
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }
    })
}
