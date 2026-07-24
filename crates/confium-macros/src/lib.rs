//! Proc-macros for Confium plugin authors.
//!
//! Planned macros (per `TODO.roadmap/02-workspace-layout.md` plugin SDK):
//!
//! - `#[plugin_interface(name = "hash", version = 0)]` — generates the
//!   `cfmp_hash_*` FFI entry-point symbols from a trait impl.
//! - `confium_api::export!()` — emits the registry submission and the
//!   `cfmp_query_interfaces` / `cfmp_metadata` boilerplate.
//!
//! Today this is a placeholder skeleton.
