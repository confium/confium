//! Implementation of the `#[plugin_interface]` proc-macro.
//!
//! For the proof-of-concept, this macro recognizes the wire protocol for
//! `name = "hash", version = 0` and emits the eight canonical hash v0
//! symbols the loader looks up at plugin-load time:
//!
//! | symbol | trait method |
//! |--------|--------------|
//! | `cfmp_hash_create`        | `HashPlugin::new`         |
//! | `cfmp_hash_output_size`   | `HashPlugin::output_size` |
//! | `cfmp_hash_block_size`    | `HashPlugin::block_size`  |
//! | `cfmp_hash_update`        | `HashPlugin::update`      |
//! | `cfmp_hash_reset`         | `HashPlugin::reset`       |
//! | `cfmp_hash_clone`         | `HashPlugin::try_clone`   |
//! | `cfmp_hash_finalize`      | `HashPlugin::finalize`    |
//! | `cfmp_hash_destroy`       | (Drop)                    |
//!
//! Other interface names produce a helpful compile error pointing at the
//! extension point. Adding a new interface = adding a `mod <name>` in
//! this file that exposes a `generate(spec, impl_block)` function and a
//! match arm in [`plugin_interface_impl`].

use proc_macro2::TokenStream;
use quote::quote;
use syn::ItemImpl;

use crate::util::parse_interface_attr;

/// Entry point invoked by the `#[plugin_interface]` attribute.
pub fn plugin_interface_impl(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> syn::Result<TokenStream> {
    let spec = parse_interface_attr(attr)?;
    let impl_block: ItemImpl = syn::parse2(item)?;

    // The macro emits both the original impl (so the trait is still
    // implemented for the user's type) and the FFI entry-point symbols.
    let original = &impl_block;

    // Extract the implementing type — used in the generated entry points
    // to construct / cast instances of it.
    let self_ty = &impl_block.self_ty;

    let ffi = match spec.name.as_str() {
        "hash" => super::interface::hash::generate_v0(self_ty)?,
        other => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                format!(
                    "the #[plugin_interface] macro does not yet support the wire protocol for \
                     `name = \"{other}\"`. The current SDK proof-of-concept only emits the \
                     `hash` v0 symbols. To add support, extend \
                     `crates/confium-macros/src/interface/` with a new submodule and add a \
                     match arm in `plugin_interface_impl`."
                ),
            ));
        }
    };

    // Stash the registered interface in a static so a future iteration
    // of `#[export]` can discover it at link time when building
    // `cfmp_query_interfaces`. The current `#[export]` macro takes the
    // interfaces list explicitly via `interfaces(...)`, so this static
    // is currently informational only.
    let name_lit = &spec.name;
    let version_lit = spec.version;
    let registration_doc = format!(
        "Confium plugin interface registered by #[plugin_interface]: \
         name = `{name_lit}`, version = `{version_lit}`."
    );

    Ok(quote! {
        #original

        #ffi

        #[doc = #registration_doc]
        #[allow(non_upper_case_globals)]
        const __CONFIUM_IFACE_HASH_NAME: &'static str = #name_lit;
        #[doc = #registration_doc]
        #[allow(non_upper_case_globals)]
        const __CONFIUM_IFACE_HASH_VERSION: u8 = #version_lit;
    })
}

pub mod hash {
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
}
