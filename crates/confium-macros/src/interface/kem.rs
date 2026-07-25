//! Wire protocol generator for the KEM interface (v0).
//!
//! Emits the `cfmp_kem_*` symbols from an
//! `impl KemPlugin for T` block. The FFI surface splits into
//! encapsulator entry points (`cfmp_kem_encapsulator_*`), decapsulator
//! entry points (`cfmp_kem_decapsulator_*`), a shared-secret size
//! query, and a keypair generator.
//!
//! Several entry points have complex parameter lists fixed by the C
//! ABI; the macro emits `#[allow(clippy::too_many_arguments)]`
//! automatically on those symbols.

use proc_macro2::TokenStream;
use quote::quote;

/// Emit the KEM v0 FFI symbols for the given implementing type.
pub fn generate_v0(self_ty: &syn::Type) -> syn::Result<TokenStream> {
    let _ = self_ty;

    Ok(quote! {
        // ---- cfmp_kem_encapsulator_create ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kem_encapsulator_create(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
            recipient_pubkey: *const std::ffi::c_void,
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
            let recipient_pubkey: &[u8] = if recipient_pubkey.is_null() || pk_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(recipient_pubkey as *const u8, pk_len as usize) }
            };
            let opts_view = if opts.is_null() {
                None
            } else {
                unsafe { ::confium_api::OptionView::from_raw_ptr(opts) }
            };
            <#self_ty as ::confium_api::plugin::kem::KemPlugin>::encapsulator_create(
                &algorithm, recipient_pubkey, opts_view,
            )
            .map(|inst| { *out = ::confium_api::OpaqueHandle::new(inst); })
            .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kem_encapsulate ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kem_encapsulate(
            handle: *mut std::ffi::c_void,
            ct_out: *mut u8,
            ct_max: u32,
            ct_len: *mut u32,
            ss_out: *mut u8,
            ss_max: u32,
            ss_len: *mut u32,
        ) -> u32 {
            if handle.is_null() || ct_len.is_null() || ss_len.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let ct_out: &mut [u8] = if ct_out.is_null() {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(ct_out, ct_max as usize) }
            };
            let ss_out: &mut [u8] = if ss_out.is_null() {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(ss_out, ss_max as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            match <#self_ty as ::confium_api::plugin::kem::KemPlugin>::encapsulate(inst, ct_out, ss_out) {
                Ok(res) => {
                    unsafe {
                        *ct_len = res.ciphertext.len() as u32;
                        *ss_len = res.shared_secret.len() as u32;
                    }
                    // Copy the actual output into the caller's buffers
                    // (the plugin may have produced more than fit; the
                    // caller's buffers are sized via
                    // shared_secret_size).
                    unsafe {
                        if !ct_out.is_empty() {
                            let n = res.ciphertext.len().min(ct_out.len());
                            std::ptr::copy_nonoverlapping(res.ciphertext.as_ptr(), ct_out.as_mut_ptr(), n);
                        }
                        if !ss_out.is_empty() {
                            let n = res.shared_secret.len().min(ss_out.len());
                            std::ptr::copy_nonoverlapping(res.shared_secret.as_ptr(), ss_out.as_mut_ptr(), n);
                        }
                    }
                    0
                }
                Err(e) => e.into_wire(),
            }
        }

        // ---- cfmp_kem_encapsulator_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kem_encapsulator_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }

        // ---- cfmp_kem_decapsulator_create ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kem_decapsulator_create(
            _cfm: *const std::ffi::c_void,
            out: *mut *mut std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
            recipient_seckey: *const std::ffi::c_void,
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
            let recipient_seckey: &[u8] = if recipient_seckey.is_null() || sk_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(recipient_seckey as *const u8, sk_len as usize) }
            };
            let opts_view = if opts.is_null() {
                None
            } else {
                unsafe { ::confium_api::OptionView::from_raw_ptr(opts) }
            };
            <#self_ty as ::confium_api::plugin::kem::KemPlugin>::decapsulator_create(
                &algorithm, recipient_seckey, opts_view,
            )
            .map(|inst| { *out = ::confium_api::OpaqueHandle::new(inst); })
            .map_or_else(|e| e.into_wire(), |_| 0u32)
        }

        // ---- cfmp_kem_decapsulate ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kem_decapsulate(
            handle: *mut std::ffi::c_void,
            ciphertext: *const u8,
            ct_len: u32,
            ss_out: *mut u8,
            ss_max: u32,
            ss_len: *mut u32,
        ) -> u32 {
            if handle.is_null() || ss_len.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            let ciphertext: &[u8] = if ciphertext.is_null() || ct_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(ciphertext, ct_len as usize) }
            };
            let ss_out: &mut [u8] = if ss_out.is_null() {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(ss_out, ss_max as usize) }
            };
            let inst = ::confium_api::OpaqueHandle::<#self_ty>::borrow_raw(handle);
            <#self_ty as ::confium_api::plugin::kem::KemPlugin>::decapsulate(inst, ciphertext, ss_out)
                .map(|n| { unsafe { *ss_len = n as u32; } 0u32 })
                .map_or_else(|e| e.into_wire(), |c| c)
        }

        // ---- cfmp_kem_decapsulator_destroy ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kem_decapsulator_destroy(
            handle: *mut std::ffi::c_void,
        ) {
            unsafe {
                ::confium_api::OpaqueHandle::<#self_ty>::from_raw(handle);
            }
        }

        // ---- cfmp_kem_shared_secret_size ----
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kem_shared_secret_size(
            _cfm: *const std::ffi::c_void,
            algorithm: *const std::os::raw::c_char,
            out_size: *mut u32,
        ) -> u32 {
            if algorithm.is_null() || out_size.is_null() {
                return ::confium_api::ErrorCode::NULL_POINTER.into_wire();
            }
            use std::ffi::CStr;
            let algorithm = match CStr::from_ptr(algorithm).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return ::confium_api::ErrorCode::INVALID_UTF8.into_wire(),
            };
            match <#self_ty as ::confium_api::plugin::kem::KemPlugin>::shared_secret_size(&algorithm) {
                Ok(size) => {
                    unsafe { *out_size = size; }
                    0
                }
                Err(e) => e.into_wire(),
            }
        }

        // ---- cfmp_kem_keypair_generate ----
        #[allow(clippy::too_many_arguments)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cfmp_kem_keypair_generate(
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
            match <#self_ty as ::confium_api::plugin::kem::KemPlugin>::keypair_generate(
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
