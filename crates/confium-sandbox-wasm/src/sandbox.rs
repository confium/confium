//! The sandbox abstraction.
//!
//! [`Sandbox`] is the trait every plugin-runtime impl satisfies (WASM
//! in-process via wasmtime here, out-of-process via IPC in
//! `confium-sandbox-process` later — see `TODO.roadmap/16`). Every
//! instance runs inside the sandbox's capability envelope: a plugin
//! cannot reach a host import it has not been granted.
//!
//! See `TODO.roadmap/15-wasm-sandboxing.md` for the design.

use std::path::PathBuf;

use crate::Result;

/// A capability a sandboxed plugin may be granted.
///
/// Capabilities are explicit, granular, and revocable. The sandbox
/// runtime checks every host-import invocation against the instance's
/// current capability set; a denied call traps with
/// [`Error::CapabilityDenied`](crate::Error::CapabilityDenied).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Plugin may call the `cfm_<name>_*` host-import family
    /// (e.g. `InterfaceAccess { name: "hash" }` enables `cfm_hash_*`).
    InterfaceAccess { name: String },
    /// Plugin may talk to this network endpoint.
    NetworkEndpoint { url: String },
    /// Plugin may reference this key (read/use, never reveal bytes).
    KeyAccess { key_id: String },
    /// Plugin may read/write this filesystem path.
    FilesystemPath {
        path: PathBuf,
        mode: FilesystemMode,
    },
}

/// Access mode for a [`Capability::FilesystemPath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilesystemMode {
    ReadOnly,
    ReadWrite,
}

/// A value passed across the sandbox boundary. Intentionally a small
/// set — structured data crosses via linear-memory copy through a
/// host import rather than being encoded into the type system.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    /// Opaque byte slice, copied into the guest's linear memory.
    Bytes(Vec<u8>),
}

/// A loaded, capability-bound plugin.
///
/// Instances are mutable: capabilities can be granted and revoked
/// between calls. A revoked capability takes effect immediately on
/// the next host-import invocation.
pub trait SandboxInstance: Send + Sync {
    /// Invoke `function` with `args`. Returns the function's results.
    fn call(&mut self, function: &str, args: &[Value]) -> Result<Vec<Value>>;

    /// Grant `cap` to this instance. Grants are idempotent.
    fn grant_capability(&mut self, cap: Capability) -> Result<()>;

    /// Revoke the matching capability. Revokes are idempotent.
    fn revoke_capability(&mut self, cap: &Capability) -> Result<()>;
}

/// A plugin runtime.
///
/// Implementations are cheap to clone: they share the underlying
/// engine and compile cache. Each [`load_module`](Sandbox::load_module)
/// produces an independent [`SandboxInstance`] with its own linear
/// memory and an empty capability set.
pub trait Sandbox: Send + Sync {
    /// Compile and link a plugin from raw WASM (or WAT, depending on
    /// the impl) bytes.
    fn load_module(&self, bytes: &[u8]) -> Result<Box<dyn SandboxInstance>>;

    /// Human-readable runtime name (e.g. `"wasmtime"`).
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_equality() {
        let a = Capability::InterfaceAccess { name: "hash".into() };
        let b = Capability::InterfaceAccess { name: "hash".into() };
        assert_eq!(a, b);

        let c = Capability::InterfaceAccess { name: "sign".into() };
        assert_ne!(a, c);
    }

    #[test]
    fn capability_clone_preserves_fields() {
        let cap = Capability::NetworkEndpoint {
            url: "https://example.com".into(),
        };
        let cloned = cap.clone();
        assert_eq!(cap, cloned);
    }

    #[test]
    fn filesystem_mode_distinct() {
        assert_ne!(FilesystemMode::ReadOnly, FilesystemMode::ReadWrite);
    }
}
