//! Public Rust API and plugin SDK for Confium.
//!
//! This crate is the bottom of the dependency stack. Everyone (core, store,
//! registry, net, tc, plugin authors) can depend on it. It does **not**
//! include the plugin loader itself.
//!
//! It exposes the shared types that plugin authors need to write a Confium
//! plugin in Rust without re-declaring the wire types:
//!
//! - Opaque handle helpers ([`OpaqueHandle`]) for boxing/unboxing Rust
//!   objects behind the type-erased `*mut c_void` plugin contract.
//! - Option map types ([`OptionMap`], [`OptionValue`]) used by the
//!   `cfmp_<iface>_create` family to pass string/u32/nested configuration
//!   from Confium to the plugin.
//! - Error conversion ([`PluginError`], [`ErrorCode`]) — the canonical
//!   numeric codes returned through the FFI surface, plus a `From` impl so
//!   plugin authors can `?` their own errors into the wire code.
//!
//! The proc-macros in `confium-macros` consume these types when generating
//! the `cfmp_<iface>_*` entry points and the `cfmp_query_interfaces` /
//! `cfmp_metadata` boilerplate. See `TODO.roadmap/02-workspace-layout.md`
//! and `TODO.roadmap/03-plugin-contract.md` for the design.

pub mod error;
pub mod handle;
pub mod metadata;
pub mod options;
pub mod plugin;

pub use error::{ErrorCode, PluginError, PluginResult};
pub use handle::OpaqueHandle;
pub use metadata::{PluginMetadata, PluginMetadataBuilder};
pub use options::{OptionMap, OptionValue, OptionView};
pub use plugin::HashPlugin;

/// Re-export of the proc-macros so plugin authors can write
/// `use confium_api::plugin_interface` without depending on
/// `confium-macros` directly.
#[doc(hidden)]
pub use confium_macros::{export, plugin_interface, plugin_metadata};
