//! Confium out-of-process plugin sandbox.
//!
//! Each plugin runs in its own subprocess, communicating with the
//! host over length-prefixed JSON-RPC frames on stdin/stdout. This is
//! the second of Confium's two sandboxing tracks (the first is the
//! in-process WASM runtime in `confium-sandbox-wasm`).
//!
//! ## Surfaces
//!
//! - [`Sandbox`] — the runtime trait (impl: [`ProcessSandbox`]).
//! - [`SandboxInstance`] — a loaded, capability-bound plugin.
//! - [`Capability`] — the capability model (interface / network /
//!   key / filesystem).
//! - [`Value`] — values crossing the sandbox boundary.
//! - [`protocol`] (public) — the wire types and helpers for the
//!   length-prefixed JSON-RPC framing.
//!
//! ## Protocol
//!
//! Every frame is `4-byte big-endian length` + `length bytes of UTF-8
//! JSON`. Requests:
//!
//! ```jsonc
//! {"method": "<function>", "args": [<value>, ...]}
//! ```
//!
//! Responses:
//!
//! ```jsonc
//! {"result": [<value>, ...]}     // success
//! {"error": {"message": "<text>"}} // failure
//! ```
//!
//! See `TODO.roadmap/08-security-model.md` § "Track B" for the
//! motivation and the OS-level restriction roadmap.

pub mod error;
pub mod process_sandbox;
pub mod protocol;
pub mod sandbox;

pub use error::Error;
pub use error::Result;
pub use process_sandbox::ProcessInstance;
pub use process_sandbox::ProcessSandbox;
pub use sandbox::Capability;
pub use sandbox::FilesystemMode;
pub use sandbox::Sandbox;
pub use sandbox::SandboxInstance;
pub use sandbox::Value;
