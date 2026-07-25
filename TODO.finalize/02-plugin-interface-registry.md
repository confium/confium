# 02 — OCP plugin interface registry

## Why

`src/ffi/plugin.rs`'s `PluginInterface` enum and `create_plugin_interface`
match arm are closed for extension. Adding the symmetric, AEAD, KDF, RNG,
signature, KEM, and keystore interfaces required to reach parity with RNP
would force seven edits to a central match statement. That violates OCP
and makes the registry the de-facto coupling point.

## Goal

Adding a new interface type = adding one new module (`src/ffi/<name>.rs`)
with a registration call. Zero edits to existing files.

## Design

### Registry trait (new: `src/ffi/registry.rs`)

```rust
pub trait PluginInterfaceKind: 'static + Send + Sync {
    /// Wire name advertised via `cfmp_query_interfaces` (e.g. "hash",
    /// "symmetric", "kem"). Must be ASCII, no NUL.
    const NAME: &'static str;

    /// Highest supported interface version this build of Confium
    /// understands.
    const MAX_VERSION: u8;

    /// Construct an opaque interface handle from the loaded library,
    /// given a negotiated version. Returns None if the version is
    /// unsupported.
    fn build(lib: &Library, version: u8) -> Result<Option<Box<dyn Any>>>;
}
```

### Registration

Each interface module calls `register_interface!` from its top:

```rust
// src/ffi/hash.rs
register_interface!(HashInterfaceKind, "hash", max_version = 0);
```

The macro expands to an `inventory::submit!` call (or a hand-rolled
linker-section registry to avoid the `inventory` dependency) that
adds the kind to a global registry at link time.

### Discovery

`create_plugin_interface` becomes:

```rust
fn create_plugin_interface(
    lib: &Library,
    name: &str,
    versions: &[u8],
) -> Result<Option<Box<dyn Any>>> {
    for kind in interfaces() {
        if kind.name() != name { continue; }
        for &v in versions.iter().rev() {
            if v > kind.max_version() { continue; }
            if let Some(iface) = (kind.build)(lib, v)? {
                return Ok(Some(iface));
            }
        }
    }
    Ok(None)
}
```

No match statement, no enum, no centralization.

### PluginInterface becomes type-erased

```rust
pub struct PluginInterface {
    name: &'static str,
    version: u8,
    inner: Box<dyn Any>,  // concrete interface struct from each module
}
```

### Per-interface downcast

Callers that need a specific interface (e.g. `Hash::new` wanting
`HashInterfaceV0`) use `plugin.interface::<HashInterfaceV0>()`:

```rust
impl Plugin {
    pub fn interface<T: 'static>(&self, name: &str) -> Option<&T> {
        self.interfaces.iter().find_map(|i| {
            (i.name == name).then(|| i.inner.downcast_ref::<T>()).flatten()
        })
    }
}
```

This replaces the `match **iface { PluginInterface::Hash(..) => ... }`
pattern that closes the enum.

## Files touched

- New: `src/ffi/registry.rs`
- Edit: `src/ffi/mod.rs` (export registry)
- Edit: `src/ffi/plugin.rs` (remove enum, simplify create/discover)
- Edit: `src/ffi/hash.rs` (register, store concrete `HashInterface`)
- Edit: `src/hash.rs` (use `plugin.interface::<HashInterface>()`)
- Edit: `src/lib.rs` (drop `PluginInterface` enum; `Plugin` holds `Vec<PluginInterface>` opaque)

## Migration

Single PR. Hash continues to work end-to-end. CI green required.

## Trade-offs

- `Box<dyn Any>` adds one heap allocation per interface and one downcast
  per lookup. Both are O(1) and dominated by the FFI call cost. Acceptable.
- A linker-section registry is more complex than `inventory` but avoids
  adding a crate dependency. Use the linker-section approach to keep deps
  minimal (Confium currently has only two: libloading + snafu).

## Out of scope

- Multiple instances of the same interface name (e.g. two different
  symmetric providers coexisting) — handled by the `Provider` layer
  already.
