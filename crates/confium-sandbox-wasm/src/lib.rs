//! Confium WASM plugin sandbox — capability-bounded execution of
//! third-party plugin modules via wasmtime.
//!
//! Confium plugins today (1.0) run in-process and are fully
//! trusted. This crate implements the sandboxed path: any language
//! that compiles to WASM (Rust, C, C++, Zig, AssemblyScript) can be
//! loaded as a Confium plugin, with explicit and revocable
//! capabilities gating every host-side effect.
//!
//! ## Surfaces
//!
//! - [`Sandbox`] — the runtime trait (impl: [`WasmSandbox`]).
//! - [`SandboxInstance`] — a loaded, capability-bound plugin.
//! - [`Capability`] — the capability model (interface / network /
//!   key / filesystem).
//! - [`Value`] — values crossing the sandbox boundary.
//! - [`HostImports`] (internal) — `cfm_*` host-import dispatch with
//!   capability gating.
//!
//! See `TODO.roadmap/15-wasm-sandboxing.md` for the full design.
//!
//! ## Status
//!
//! Skeleton + capability-gating dispatch are in place. The host
//! imports are stubs (deterministic return values) so the end-to-end
//! pipeline can be exercised before the real hash / net / key
//! handlers in confium-core / confium-net / confium-store are wired
//! up.

pub mod error;
pub mod imports;
pub mod sandbox;
pub mod wasm;

pub use error::Error;
pub use error::Result;
pub use sandbox::Capability;
pub use sandbox::FilesystemMode;
pub use sandbox::Sandbox;
pub use sandbox::SandboxInstance;
pub use sandbox::Value;
pub use wasm::WasmInstance;
pub use wasm::WasmSandbox;
