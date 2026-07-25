//! Wire protocol generator for the AEAD interface (v0).
//!
//! Emits the eight `cfmp_aead_*` symbols from an
//! `impl AeadPlugin for T` block. The trait lives in
//! `confium_api::plugin::aead::AeadPlugin`.

use proc_macro2::TokenStream;
use quote::quote;

/// Emit the AEAD v0 FFI symbols for the given implementing type.
pub fn generate_v0(self_ty: &syn::Type) -> syn::Result<TokenStream> {
    let _ = self_ty;

    Ok(quote! {
        // ---- cfmp_aead_create ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_aead_create(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
            key: *const std::ffi::c_void,
            key_len: u32,
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
            let opts_view = if opts.is_null() {
                None
            } else {
                unsafe { ::confium_api::OptionView::from_raw_ptr(opts) }
            };
            <#self_ty as ::confium_api::plugin::aead::AeadPlugin>::create_with_key(
                &algorithm, key, opts_view,
            )
            .map(|inst| { *out = ::confium_api::OpaqueHandle::new(inst); })
            .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_aead_set_nonce ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_aead_set_nonce(
            handle: *mut std::ffi::c_void,
            nonce: *const u8,
            len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let nonce: &[u8] = if nonce.is_null() || len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(nonce, len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::aead::AeadPlugin>::set_nonce(inst, nonce)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_aead_associated_data_update ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_aead_associated_data_update(
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
            <#self_ty as ::confium_api::plugin::aead::AeadPlugin>::associated_data_update(inst, data)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_aead_encrypt_update ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_aead_encrypt_update(
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
            <#self_ty as ::confium_api::plugin::aead::AeadPlugin>::encrypt_update(inst, input, output)
                .map(|n| { *out_len = n as u32; 0u32 })
                .map_or_else(|e| e.into_wire(), |c| c)
        }

        // ---- cfmp_aead_decrypt_update ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_aead_decrypt_update(
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
            <#self_ty as ::confium_api::plugin::aead::AeadPlugin>::decrypt_update(inst, input, output)
                .map(|n| { *out_len = n as u32; 0u32 })
                .map_or_else(|e| e.into_wire(), |c| c)
        }

        // ---- cfmp_aead_finalize ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_aead_finalize(
            handle: *mut std::ffi::c_void,
            tag: *mut u8,
            tag_max: u32,
            tag_len: *mut u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let tag_len = match tag_len.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            let avail = tag_max as usize;
            let tag: &mut [u8] = if tag.is_null() {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(tag, avail) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::aead::AeadPlugin>::finalize(inst, tag)
                .map(|n| { *tag_len = n as u32; 0u32 })
                .map_or_else(|e| e.into_wire(), |c| c)
        }

        // ---- cfmp_aead_verify_tag ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_aead_verify_tag(
            handle: *mut std::ffi::c_void,
            tag: *const u8,
            len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let tag: &[u8] = if tag.is_null() || len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(tag, len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::aead::AeadPlugin>::verify_tag(inst, tag)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_aead_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_aead_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }
    })
}
