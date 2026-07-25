//! Wire protocol generator for the asymmetric signature interface (v0).
//!
//! Emits the `cfmp_sig_*` symbols from an
//! `impl SignaturePlugin for T` block. The FFI surface splits into
//! signer entry points (`cfmp_sig_signer_*`), verifier entry points
//! (`cfmp_sig_verifier_*`), and a keypair generator
//! (`cfmp_sig_keypair_generate`).
//!
//! Several entry points have complex parameter lists fixed by the C
//! ABI; the macro emits `#[allow(clippy::too_many_arguments)]`
//! automatically on those symbols.

use proc_macro2::TokenStream;
use quote::quote;

/// Emit the signature v0 FFI symbols for the given implementing type.
pub fn generate_v0(self_ty: &syn::Type) -> syn::Result<TokenStream> {
    let _ = self_ty;

    Ok(quote! {
        // ---- cfmp_sig_signer_create ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_signer_create(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
            secret_key: *const std::ffi::c_void,
            sk_len: u32,
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
            let secret_key: &[u8] = if secret_key.is_null() || sk_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(secret_key as *const u8, sk_len as usize) }
            };
            let opts_view = if opts.is_null() {
                None
            } else {
                unsafe { ::confium_api::OptionView::from_raw_ptr(opts) }
            };
            <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::signer_create(
                &algorithm, secret_key, opts_view,
            )
            .map(|inst| { *out = ::confium_api::OpaqueHandle::new(inst); })
            .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_sig_signer_set_hash ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_signer_set_hash(
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
            <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::set_hash(inst, &name)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_sig_signer_update ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_signer_update(
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
            <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::update(inst, data)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_sig_signer_finalize ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_signer_finalize(
            handle: *mut std::ffi::c_void,
            sig_out: *mut u8,
            sig_max: u32,
            sig_len: *mut u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let sig_len = match sig_len.as_mut() {
                Some(o) => o,
                None => return ::confium_api::ErrorCode::NULL_POINTER.into_wire(),
            };
            let avail = sig_max as usize;
            let sig_out: &mut [u8] = if sig_out.is_null() {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(sig_out, avail) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::signer_finalize(inst, sig_out)
                .map(|n| { *sig_len = n as u32; 0u32 })
                .map_or_else(|e| e.into_wire(), |c| c)
        }

        // ---- cfmp_sig_signer_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_signer_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }

        // ---- cfmp_sig_verifier_create ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_verifier_create(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
            public_key: *const std::ffi::c_void,
            pk_len: u32,
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
            let public_key: &[u8] = if public_key.is_null() || pk_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(public_key as *const u8, pk_len as usize) }
            };
            let opts_view = if opts.is_null() {
                None
            } else {
                unsafe { ::confium_api::OptionView::from_raw_ptr(opts) }
            };
            <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::verifier_create(
                &algorithm, public_key, opts_view,
            )
            .map(|inst| { *out = ::confium_api::OpaqueHandle::new(inst); })
            .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_sig_verifier_set_hash ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_verifier_set_hash(
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
            <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::set_hash(inst, &name)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_sig_verifier_update ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_verifier_update(
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
            <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::update(inst, data)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_sig_verifier_finalize ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_verifier_finalize(
            handle: *mut std::ffi::c_void,
            sig: *const u8,
            sig_len: u32,
        ) -> u32 {
            if handle.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let sig: &[u8] = if sig.is_null() || sig_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(sig, sig_len as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::verifier_finalize(inst, sig)
                .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_sig_verifier_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_verifier_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }

        // ---- cfmp_sig_keypair_generate ----
        //
        // Complex parameter list fixed by the C ABI (cfm, algorithm,
        // seed+seed_len, pk_out+pk_max+pk_len, sk_out+sk_max+sk_len).
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_sig_keypair_generate(
            _cfm: *const std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
            seed: *const u8,
            seed_len: u32,
            pk_out: *mut u8,
            pk_max: u32,
            pk_len: *mut u32,
            sk_out: *mut u8,
            sk_max: u32,
            sk_len: *mut u32,
        ) -> u32 {
            use std::ffi::CStr;
            if algorithm.is_null() || pk_len.is_null() || sk_len.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let algorithm = match CStr::from_ptr(algorithm).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return ::confium_api::ErrorCode::INVALID_UTF8.into_wire(),
            };
            let seed: Option<&[u8]> = if seed.is_null() || seed_len == 0 {
                None
            } else {
                Some(unsafe { std::slice::from_raw_parts(seed, seed_len as usize) })
            };
            match <#self_ty as ::confium_api::plugin::signature::SignaturePlugin>::keypair_generate(
                &algorithm, seed, None,
            ) {
                Ok(kp) => {
                    let pk = &kp.public_key;
                    let sk = &kp.secret_key;
                    if pk.len() > pk_max as usize || sk.len() > sk_max as usize {
                        return ::confium_api::ErrorCode::INSUFFICIENT_BUFFER.into_wire();
                    }
                    unsafe {
                        if !pk_out.is_null() {
                            std::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, pk.len());
                        }
                        if !sk_out.is_null() {
                            std::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, sk.len());
                        }
                        *pk_len = pk.len() as u32;
                        *sk_len = sk.len() as u32;
                    }
                    0
                }
                Err(e) => e.into_wire(),
            }
        }
    })
}
