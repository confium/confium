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
//! ## Supported interfaces
//!
//! The `#[plugin_interface]` macro recognizes the wire protocol for all
//! Confium crypto interfaces at version 0: `hash`, `cipher`, `aead`,
//! `kdf`, `rng`, `signature`, `kem`, and `keyfmt`. Each interface emits
//! its canonical `cfmp_<iface>_*` symbol set, dispatching through the
//! corresponding trait in `confium_api::plugin`.
//!
//! Interfaces with complex parameter lists (`signature`, `kem`,
//! `keyfmt`) automatically get `#[allow(clippy::too_many_arguments)]`
//! on the affected symbols, since the parameter count is fixed by the
//! C ABI.
//!
//! Interface auto-discovery: every `#[plugin_interface]` attribute
//! registers its `(name, version)` pair at link time via `inventory`.
//! The `#[export]` macro iterates these registrations at runtime to
//! populate `cfmp_query_interfaces`, so plugin authors do not need to
//! repeat the interface list in `#[export]`.
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
/// Supported interfaces (all at version 0): `hash`, `cipher`, `aead`,
/// `kdf`, `rng`, `signature`, `kem`, `keyfmt`. Each dispatches through
/// the corresponding trait in `confium_api::plugin`.
///
/// Place this attribute on an `impl Trait for Type` block. Example for
/// the hash interface:
///
/// ```ignore
/// # use confium_api::plugin_interface;
/// # use confium_api::HashPlugin;
/// # struct MyHash;
/// #[plugin_interface(name = "hash", version = 0)]
/// impl HashPlugin for MyHash {
///     // ... methods ...
/// }
/// ```
///
/// The cipher interface advertises under the wire name `symmetric`
/// (matching the loader-side `CipherKind`); all other interfaces use
/// the same name for both the attribute and the wire protocol.
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
