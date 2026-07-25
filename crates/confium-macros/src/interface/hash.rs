//! Wire protocol generator for the hash interface (v0).
//!
//! This module emits the eight `cfmp_hash_*` symbols from an
//! `impl HashPlugin for T` block. The trait lives in
//! `confium_api::plugin::hash::HashPlugin` and is matched one method
//! to one symbol per the loader's per-interface vtable
//! (`crates/confium-core/src/ffi/hash.rs`).

use proc_macro2::TokenStream;
use quote::quote;

/// Emit the hash v0 FFI symbols for the given implementing type.
pub fn generate_v0(self_ty: &syn::Type) -> syn::Result<TokenStream> {
    let _ = self_ty; // currently unused at the type level — symbols are generic.

    Ok(quote! {
        // ---- cfmp_hash_create ----
        //
        // Wire: extern "C" fn(*const Confium, *mut *mut c_void,
        //                     *const c_char, *const OptionMap) -> u32
        //
        // The trait method `HashPlugin::new(name, opts)` returns
        // Self; we box it via `OpaqueHandle` and hand the raw
        // pointer back to the loader.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_hash_create(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            name: *const std::os::raw::c_char,
            opts: *const std::ffi::c_void,
        ) -> u32 {
            use std::ffi::CStr;
            let out = match out.as_mut() {
                Some(o) => o,
                None => {
                    return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
                }
            };
            let name = if name.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            } else {
                match CStr::from_ptr(name).to_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return ::confium_api::ErrorCode::INVALID_UTF8.into_wire();
                    }
                }
            };
            let opts_view = if opts.is_null() {
                None
            } else {
                // SAFETY: the loader hands us a &OptionMap borrow
                // valid for this call.
                unsafe {
                    ::confium_api::OptionView::from_raw_ptr(opts as *const std::ffi::c_void)
                }
            };
            // The plugin author implements the trait on their type;
            // dispatch through the trait object isn't needed because
            // the impl block is right next to this symbol.
            <#self_ty as ::confium_api::plugin::hash::HashPlugin>::create_with_opts(
                &name,
                opts_view,
            )
            .map(|inst| {
                *out = ::confium_api::OpaqueHandle::new(inst);
            })
            .map_or_else(
                |e| e.into_wire(),
                |_| 0u32,
            )
        }

        // ---- cfmp_hash_output_size ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_hash_output_size(
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
            let size = <#self_ty as ::confium_api::plugin::hash::HashPlugin>::output_size(&inst);
            *out = size;
            0
        }

        // ---- cfmp_hash_block_size ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_hash_block_size(
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
            let size = <#self_ty as ::confium_api::plugin::hash::HashPlugin>::block_size(&inst);
            *out = size;
            0
        }

        // ---- cfmp_hash_update ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_hash_update(
            handle: *mut std::ffi::c_void,
            data: *const u8,
            len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let data = if data.is_null() || len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::hash::HashPlugin>::update(inst, data)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_hash_reset ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_hash_reset(
            handle: *mut std::ffi::c_void,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::hash::HashPlugin>::reset(inst)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_hash_clone ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_hash_clone(
            src: *mut std::ffi::c_void,
            dst: *mut *mut std::ffi::c_void,
        ) -> u32 {
            let dst = match dst.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            if src.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(src);
            match <#self_ty as ::confium_api::plugin::hash::HashPlugin>::try_clone(inst) {
                Ok(clone) => {
                    *dst = ::confium_api::OpaqueHandle::new(clone);
                    0
                }
                Err(e) => e.into_wire(),
            }
        }

        // ---- cfmp_hash_finalize ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_hash_finalize(
            handle: *mut std::ffi::c_void,
            out: *mut u8,
            len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let out = if out.is_null() || len == 0 {
                return ::confium_api::ErrorCode::INSUFFICIENT_BUFFER.into_wire();
            } else {
                unsafe { std::slice::from_raw_parts_mut(out, len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::hash::HashPlugin>::finalize(inst, out)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_hash_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_hash_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            // SAFETY: the loader invokes `destroy` exactly once per
            // pointer produced by `cfmp_hash_create`. `from_raw`
            // handles NULL by doing nothing.
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }
    })
}
