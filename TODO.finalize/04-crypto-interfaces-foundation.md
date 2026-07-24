# 04 — Crypto interfaces foundation (shared traits)

## Why

Once TODO #02 lands, each crypto interface (symmetric, AEAD, KDF, RNG,
signature, KEM, key-store) is a self-contained module. They all share
common domain concepts:

- Opaque handles (`*mut FFIHash`, `*mut FFICipher`, etc.)
- Versioned vtable structs
- "Build the interface from a loaded library at a given version"
  function (the `create_<name>_interface` pattern currently copied
  into every module)
- Algorithm name resolution

Centralizing the shared patterns gives DRY without coupling.

## Goal

A single `src/crypto/` module that holds shared types and helpers, used
by every `src/ffi/<name>.rs` interface.

## Design

### Opaque-handle helper

```rust
// src/crypto/handle.rs
pub struct OpaqueHandle(#[allow(dead_code)] *mut ());

unsafe impl Send for OpaqueHandle {}
unsafe impl Sync for OpaqueHandle {}
```

Used as `*mut FFIFoo` replacement target. Plugins produce/destroy
these via their vtable.

### Algorithm identifier

```rust
// src/crypto/algorithm.rs
pub struct AlgorithmName(pub(crate) std::ffi::CString);

impl AlgorithmName {
    pub fn new(name: &str) -> Result<Self> { ... }
    pub fn as_ptr(&self) -> *const c_char { ... }
    pub fn as_str(&self) -> &str { ... }
}
```

### Vtable symbol helper

Replaces the per-module `get_plugin_symbol::<HashCreateFnV0>(...)` copy:

```rust
// src/crypto/symbol.rs
pub(crate) fn lookup<T: Copy>(
    lib: &Library,
    symbol: &'static [u8],
    error_kind: crate::error::PluginSymbolSnafu,
) -> Result<Box<T>> { ... }
```

Used by every interface's `build()`.

### Versioned vtable pattern

```rust
// src/crypto/versioned.rs
pub trait Versioned {
    type V0; // generated per-interface
    const MAX_VERSION: u8;
}
```

Hmm, this might be over-abstraction. Per the system prompt rule
"Three similar lines is better than a premature abstraction", don't
extract this trait unless three concrete uses emerge. **Defer**; keep
the per-module `create_<name>_interface` until we have ≥3 interfaces.

## Files

- New: `src/crypto/mod.rs` — declares the module
- New: `src/crypto/handle.rs` — `OpaqueHandle`
- New: `src/crypto/algorithm.rs` — `AlgorithmName`
- New: `src/crypto/symbol.rs` — `lookup<T>`
- Edit: `src/lib.rs` — `pub mod crypto;`
- Edit: each `src/ffi/<name>.rs` — replace `get_plugin_symbol` calls
  with `crate::crypto::symbol::lookup(...)`

## Acceptance

- `cargo build` clean
- `cargo clippy -- -D warnings` clean
- `cargo deny check` clean
- The new shared helpers are exercised by every interface's tests.

## Dependency

- TODO #02 (registry) must land first so modules are decoupled.
