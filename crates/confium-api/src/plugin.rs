//! Traits plugin authors implement for each Confium interface.
//!
//! Each sub-module mirrors one interface's wire protocol: the trait
//! method set matches the `cfmp_<iface>_*` symbols one-for-one. The
//! `#[plugin_interface]` proc-macro dispatches on the trait to emit the
//! FFI entry points.

pub mod hash;

pub use hash::HashPlugin;
