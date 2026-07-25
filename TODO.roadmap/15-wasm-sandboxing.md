# 15 — WASM sandboxing

**Status**: SHIPPED. crates/confium-sandbox-wasm + confium-sandbox-process.

WASM sandbox via wasmtime 27 with capability-based access control.
Capability types: InterfaceAccess, NetworkEndpoint, KeyAccess,
FilesystemPath. Grant/revoke per instance.

Out-of-process sandbox via subprocess IPC (JSON-RPC over stdin/stdout).
Shared Sandbox/SandboxInstance trait across both implementations.

Tests: inline WAT compilation, capability gating (denied → sentinel,
granted → success), grant-then-revoke, multi-call independence.
