//! Wire protocol generator for the KDF interface (v0).
//!
//! Emits the eight `cfmp_kdf_*` symbols from an
//! `impl KdfPlugin for T` block.

use proc_macro2::TokenStream;
use quote::quote;

/// Emit the KDF v0 FFI symbols for the given implementing type.
pub fn generate_v0(self_ty: &syn::Type) -> syn::Result<TokenStream> {
    let _ = self_ty;

    Ok(quote! {
        // ---- cfmp_kdf_create ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kdf_create(
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
            <#self_ty as ::confium_api::plugin::kdf::KdfPlugin>::create(&algorithm, opts_view)
                .map(|inst| { *out = ::confium_api::OpaqueHandle::new(inst); })
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kdf_set_salt ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kdf_set_salt(
            handle: *mut std::ffi::c_void,
            salt: *const u8,
            len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let salt: &[u8] = if salt.is_null() || len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(salt, len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::kdf::KdfPlugin>::set_salt(inst, salt)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kdf_set_iterations ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kdf_set_iterations(
            handle: *mut std::ffi::c_void,
            iterations: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::kdf::KdfPlugin>::set_iterations(inst, iterations)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kdf_set_memory_cost ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kdf_set_memory_cost(
            handle: *mut std::ffi::c_void,
            bytes: u64,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::kdf::KdfPlugin>::set_memory_cost(inst, bytes)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kdf_set_parallelism ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kdf_set_parallelism(
            handle: *mut std::ffi::c_void,
            lanes: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::kdf::KdfPlugin>::set_parallelism(inst, lanes)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kdf_set_hash ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kdf_set_hash(
            handle: *mut std::ffi::c_void,
            hash_name: *const std::os::raw::c_char,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            if hash_name.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            use std::ffi::CStr;
            let name = match CStr::from_ptr(hash_name).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return ::confium_api::ErrorCode::INVALID_UTF8.into_wire(),
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::kdf::KdfPlugin>::set_hash(inst, &name)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kdf_derive ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kdf_derive(
            handle: *mut std::ffi::c_void,
            input: *const u8,
            input_len: u32,
            out: *mut u8,
            out_len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let input: &[u8] = if input.is_null() || input_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(input, input_len as usize) }
            };
            let out: &mut [u8] = if out.is_null() || out_len == 0 {
                return ::confium_api::ErrorCode::INSUFFICIENT_BUFFER.into_wire();
            } else {
                unsafe { std::slice::from_raw_parts_mut(out, out_len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::kdf::KdfPlugin>::derive(inst, input, out)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kdf_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kdf_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }
    })
}
