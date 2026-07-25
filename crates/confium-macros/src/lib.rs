//! Proc-macros for Confium plugin authors.
//!
//! Two macros reduce the per-plugin boilerplate that would otherwise be
//! hand-rolled `extern "C"` symbols plus the plugin lifecycle hooks:
//!
//! - [`macro@plugin_interface`] on an `impl Trait for Type` block emits
//!   the `cfmp_<iface>_*` FFI entry-point symbols from the trait methods.
//! - [`macro@export`] emits the plugin lifecycle symbols
//!   (`cfmp_interface_version`, `cfmp_initialize`, `cfmp_finalize`,
//!   `cfmp_query_interfaces`) plus the optional `cfmp_metadata` symbol
//!   when paired with [`macro@plugin_metadata`].
//!
//! ## Status
//!
//! This is a **minimal viable SDK** that proves the concept for the hash
//! interface (v0). The `#[plugin_interface]` macro recognizes the wire
//! protocol for `name = "hash"` and emits the eight canonical hash v0
//! symbols (`cfmp_hash_create`, `_update`, `_finalize`, etc.). Other
//! interface names will currently produce a helpful compile error
//! directing the plugin author to the macro extension point.
//!
//! See `TODO.roadmap/03-plugin-contract.md` for the wire contract and
//! `crates/confium-api/src/` for the shared types the macros consume.

mod export;
mod interface;
mod metadata;
mod util;

use proc_macro::TokenStream;

/// Attribute macro that emits the `cfmp_<iface>_*` FFI entry-point
/// symbols for the wire protocol named by `name = "..."`.
///
/// Place this attribute on an `impl HashPlugin for MyHash` block to emit
/// the `cfmp_hash_*` FFI entry-point symbols. The trait `HashPlugin` is
/// declared in `confium_api::plugin::hash::HashPlugin` and matches the
/// hash v0 wire protocol one method per symbol.
///
/// Example:
///
/// ```ignore
/// # use confium_api::plugin_interface;
/// # use confium_api::OpaqueHandle;
/// # struct MyHash;
/// #
/// # trait HashPlugin {
/// #     fn output_size(&self) -> u32 { 0 }
/// #     fn block_size(&self) -> u32 { 0 }
/// #     fn update(&mut self, _data: &[u8]) {}
/// #     fn reset(&mut self) {}
/// #     fn try_clone(&self) -> Self where Self: Sized { MyHash }
/// #     fn finalize(&mut self, _out: &mut [u8]) {}
/// # }
/// #[plugin_interface(name = "hash", version = 0)]
/// impl HashPlugin for MyHash {
///     // ... methods ...
/// }
/// ```
#[proc_macro_attribute]
pub fn plugin_interface(attr: TokenStream, item: TokenStream) -> TokenStream {
    interface::plugin_interface_impl(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Attribute used together with [`macro@export`] to attach static
/// registry metadata to the plugin. The strings are leaked at plugin
/// load time and exposed through the generated `cfmp_metadata` symbol.
///
/// Example:
///
/// ```ignore
/// # use confium_macros::{export, plugin_metadata};
/// #[plugin_metadata(
///     name = "mock-hash",
///     version = "0.1.0",
///     vendor = "confium",
///     license = "BSD-2-Clause",
/// )]
/// #[export]
/// struct Plugin;
/// ```
#[proc_macro_attribute]
pub fn plugin_metadata(attr: TokenStream, item: TokenStream) -> TokenStream {
    metadata::plugin_metadata_impl(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Emits the plugin lifecycle symbols:
///
/// - `cfmp_interface_version` → returns `0` (current plugin contract).
/// - `cfmp_initialize` / `cfmp_finalize` → no-op success.
/// - `cfmp_query_interfaces` → packed `name\0version\0` byte stream
///   enumerating the interfaces registered by `#[plugin_interface]` in
///   this crate.
/// - `cfmp_metadata` → present only when `#[plugin_metadata]` is used
///   on the same item.
///
/// Place it on any item in the crate root of your plugin's `cdylib`:
///
/// ```ignore
/// # use confium_macros::export;
/// #[export]
/// struct Plugin;
/// ```
#[proc_macro_attribute]
pub fn export(attr: TokenStream, item: TokenStream) -> TokenStream {
    export::export_impl(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
