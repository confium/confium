//! Link-time registry of interfaces declared in a plugin crate.
//!
//! Each `#[plugin_interface(name = "...", version = N)]` attribute
//! submits a [`RegisteredInterface`] entry to this registry via
//! `inventory`. The `#[export]` macro iterates the registry at runtime
//! (inside `cfmp_query_interfaces`) to build the packed
//! `name\0version\0` payload the loader parses — so plugin authors no
//! longer need to repeat the interface list in the `#[export]`
//! attribute.
//!
//! This is the plugin-side mirror of `confium_core::ffi::registry`: the
//! core registry maps interface names to builder functions; this
//! registry maps interface names to the versions a single plugin
//! advertises.

/// One `(name, version)` pair that a plugin's `#[plugin_interface]`
/// attribute declared. Collected at link time via `inventory`.
pub struct RegisteredInterface {
    /// Wire name the plugin advertises via `cfmp_query_interfaces`.
    /// This is the name the loader's registry (`PluginInterfaceKind`)
    /// recognizes — e.g. `"hash"`, `"symmetric"` (not `"cipher"`).
    pub name: &'static str,
    /// Version of the wire protocol the plugin implements.
    pub version: u8,
}

inventory::collect!(RegisteredInterface);

/// Re-export of `inventory::submit!` under a `confium_api`-owned path so
/// the `#[plugin_interface]` proc-macro can emit registrations through
/// `$crate` without forcing every plugin crate to list `inventory` as a
/// direct dependency. The `submit!` macro's internal `$crate`
/// references still resolve to the `inventory` crate (macros are
/// hygienic), so this re-export is sound.
#[doc(hidden)]
pub use inventory::submit as inventory_submit;

/// Submit a [`RegisteredInterface`] to the link-time registry. Thin
/// wrapper around `inventory::submit!` so the `#[plugin_interface]`
/// proc-macro can emit registrations through `confium_api` without
/// forcing every plugin crate to depend on `inventory` directly.
#[macro_export]
macro_rules! register_interface {
    ($name:expr, $version:expr) => {
        $crate::registry::inventory_submit! {
            $crate::registry::RegisteredInterface {
                name: $name,
                version: $version,
            }
        }
    };
}

/// Iterator over every interface registered in the linked plugin crate.
/// Used by the `#[export]` macro to populate `cfmp_query_interfaces`
/// without requiring the plugin author to redeclare the list.
pub fn iter() -> impl Iterator<Item = &'static RegisteredInterface> {
    inventory::iter::<RegisteredInterface>.into_iter()
}
