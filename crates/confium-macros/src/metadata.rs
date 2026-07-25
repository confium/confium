//! Implementation of the `#[plugin_metadata]` proc-macro.
//!
//! In the current SDK, metadata is declared inline on the `#[export]`
//! attribute via its `metadata(...)` sub-argument. The
//! `#[plugin_metadata]` attribute is recognized for forward
//! compatibility and ergonomics, but the recommended pattern today is:
//!
//! ```ignore
//! # use confium_macros::export;
//! #[export(
//!     metadata(
//!         name = "mock-hash",
//!         version = "0.1.0",
//!         vendor = "confium",
//!         license = "BSD-2-Clause",
//!     ),
//! )]
//! struct Plugin;
//! ```
//!
//! Applying `#[plugin_metadata(...)]` to the same item as `#[export]`
//! is supported but currently does nothing — the metadata fields must
//! still be passed inline to `#[export]`. Future work will thread the
//! fields through a marker attribute (see `TODO.finalize/` for the
//! tracked cleanup).

use proc_macro2::TokenStream;
use quote::quote;

/// Entry point invoked by the `#[plugin_metadata]` attribute.
///
/// Currently a no-op marker — the metadata is declared inline on
/// `#[export(metadata(...))]`. The attribute is accepted so plugin
/// authors who write it don't hit a compile error today, and so the
/// eventual coordinated-attribute design has a stable target.
pub fn plugin_metadata_impl(
    _attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> syn::Result<TokenStream> {
    Ok(quote! {
        #[doc = "confium-plugin-metadata (forward-compat marker; see export! docs)"]
        #item
    })
}
