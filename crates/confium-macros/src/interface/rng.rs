//! Wire protocol generator for the RNG interface (v0).
//!
//! Emits the five `cfmp_rng_*` symbols from an
//! `impl RngPlugin for T` block.

use proc_macro2::TokenStream;
use quote::quote;

/// Emit the RNG v0 FFI symbols for the given implementing type.
pub fn generate_v0(self_ty: &syn::Type) -> syn::Result<TokenStream> {
    let _ = self_ty;

    Ok(quote! {
        // ---- cfmp_rng_create ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_rng_create(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
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
            let opts_view = if opts.is_null() {
                None
            } else {
                unsafe { ::confium_api::OptionView::from_raw_ptr(opts) }
            };
            <#self_ty as ::confium_api::plugin::rng::RngPlugin>::create(&algorithm, opts_view)
                .map(|inst| { *out = ::confium_api::OpaqueHandle::new(inst); })
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_rng_reseed ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_rng_reseed(
            handle: *mut std::ffi::c_void,
            data: *const u8,
            len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let data: &[u8] = if data.is_null() || len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::rng::RngPlugin>::reseed(inst, data)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_rng_add_entropy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_rng_add_entropy(
            handle: *mut std::ffi::c_void,
            data: *const u8,
            len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let data: &[u8] = if data.is_null() || len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::rng::RngPlugin>::add_entropy(inst, data)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_rng_generate ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_rng_generate(
            handle: *mut std::ffi::c_void,
            out: *mut u8,
            len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let out: &mut [u8] = if out.is_null() || len == 0 {
                return ::confium_api::ErrorCode::INSUFFICIENT_BUFFER.into_wire();
            } else {
                unsafe { std::slice::from_raw_parts_mut(out, len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::rng::RngPlugin>::generate(inst, out)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_rng_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_rng_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }
    })
}
