//! Implementation of the `#[plugin_interface]` proc-macro.
//!
//! The macro inspects the `name = "..."` argument and dispatches to a
//! per-interface generator submodule. Each submodule emits the
//! `cfmp_<iface>_*` FFI entry-point symbols the loader looks up at
//! plugin-load time, plus an `inventory` submission that registers the
//! `(name, version)` pair so [`macro@crate::export`] can auto-discover
//! it.
//!
//! Adding a new interface = adding a `mod <name>` in `mod.rs` that
//! exposes a `generate_v0(self_ty)` function and a match arm in
//! [`plugin_interface_impl`]. No existing code changes.

mod aead;
mod cipher;
mod hash;
mod kdf;
mod kem;
mod keyfmt;
mod rng;
mod signature;

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
        "hash" => hash::generate_v0(self_ty)?,
        "cipher" => cipher::generate_v0(self_ty)?,
        "aead" => aead::generate_v0(self_ty)?,
        "kdf" => kdf::generate_v0(self_ty)?,
        "rng" => rng::generate_v0(self_ty)?,
        "signature" => signature::generate_v0(self_ty)?,
        "kem" => kem::generate_v0(self_ty)?,
        "keyfmt" => keyfmt::generate_v0(self_ty)?,
        other => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                format!(
                    "the #[plugin_interface] macro does not yet support the wire protocol for \
                     `name = \"{other}\"`. Supported interfaces are: `hash`, `cipher`, `aead`, \
                     `kdf`, `rng`, `signature`, `kem`, `keyfmt`. To add support, extend \
                     `crates/confium-macros/src/interface/` with a new submodule and add a \
                     match arm in `plugin_interface_impl`."
                ),
            ));
        }
    };

    // Register the interface via `inventory` so `#[export]` can
    // auto-discover it without the plugin author redeclaring the list.
    // The wire name may differ from the attribute name (e.g. `cipher`
    // advertises as `symmetric`); the per-interface generator owns that
    // mapping.
    let wire_name = wire_name_for(&spec.name);
    let version_lit = spec.version;
    let registration_doc = format!(
        "Confium plugin interface registered by #[plugin_interface]: \
         wire name = `{wire_name}`, version = `{version_lit}`."
    );

    Ok(quote! {
        #original

        #ffi

        #[doc = #registration_doc]
        ::confium_api::register_interface!(#wire_name, #version_lit);
    })
}

/// Map a macro attribute name to the wire name advertised via
/// `cfmp_query_interfaces`. Most interfaces advertise under the same
/// name they use for their symbol prefix, but a few differ (notably
/// `cipher` → `symmetric`) to match the loader-side registry kind.
fn wire_name_for(attr_name: &str) -> &'static str {
    match attr_name {
        "hash" => "hash",
        "cipher" => "symmetric",
        "aead" => "aead",
        "kdf" => "kdf",
        "rng" => "rng",
        "signature" => "signature",
        "kem" => "kem",
        "keyfmt" => "keyfmt",
        _ => "unknown",
    }
}
