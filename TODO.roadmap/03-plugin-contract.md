# 03 — Plugin Contract

## What a plugin is

A Confium plugin is a dynamic library (`.so` / `.dylib` / `.dll`) that:

1. **Bootstraps**: exports `cfmp_interface_version`, `cfmp_initialize`, `cfmp_finalize`, `cfmp_query_interfaces`.
2. **Declares interfaces**: `cfmp_query_interfaces` returns a packed `name\0version\0` byte stream naming the interface types the plugin implements (e.g. `hash\0\0` for a hash-only plugin, or `hash\0\0cipher\0\0\0` for a multi-interface plugin).
3. **Implements per-interface symbols**: for each interface it advertises, the plugin exports the `cfmp_<iface>_*` symbols at the negotiated version.

## Interface versioning

Each interface has independent versioning. A plugin can implement hash v0 and cipher v1 simultaneously. Confium negotiates the highest mutually supported version per interface.

The `cfmp_query_interfaces` payload is `name\0version_byte\0` repeated, terminated by an empty name:

```
b"hash\0\x00\x00cipher\0\x01\x00\0"  // hash v0, cipher v1
```

(Note: version is one byte, then a NUL terminator. So each entry is `name` + `\0` + version_byte + `\0`.)

## Dependency declaration (new)

Plugins need to depend on other plugins (slide 12 of the NIST deck: "Each plugin needs some way of specifying dependencies"). Today, the `cfmp_initialize(cfm, opts)` callback gives the plugin a `*mut Confium` handle, but the plugin has no way to **require** that another plugin (say, `botan-3.x`) is loaded before it runs.

Proposed addition: the plugin declares its dependencies in `cfmp_query_interfaces` (or a new `cfmp_query_dependencies`), and Confium refuses to load the plugin unless its dependencies are satisfied.

Wire format:

```c
const CFMDependency* cfmp_query_dependencies(void);
```

```c
#[repr(C)]
pub struct CFMDependency {
    pub kind: CFMDependencyKind,    // Provider/Store/Network/MinConfiumVersion
    pub name: *const c_char,        // "botan", "openssl", "confium-core"
    pub version_range: *const c_char, // ">=3.0,<4.0", SemVer range
}
```

Confium resolves these before invoking `cfmp_initialize`. Unmet dependencies fail with `Error::PluginDependencyUnmet` (new error variant + `ErrorCode::PLUGIN_DEPENDENCY_UNMET = 27`).

## Plugin metadata

A separate, optional call exposes metadata for the registry:

```c
const CFMPluginMetadata* cfmp_metadata(void);
```

```c
#[repr(C)]
pub struct CFMPluginMetadata {
    pub name: *const c_char,            // "botan"
    pub version: *const c_char,         // "3.2.0"
    pub vendor: *const c_char,          // "Ribose"
    pub license: *const c_char,         // "BSD-2-Clause"
    pub homepage: *const c_char,        // "https://botan.randombit.net"
    pub description: *const c_char,     // "Botan 3.x crypto provider plugin"
    pub homepage_url: *const c_char,
    pub source_url: *const c_char,
    pub issue_tracker_url: *const c_char,
}
```

The registry scraper (see `#06`) reads this to populate the index. Plugins that don't export `cfmp_metadata` can still be loaded by Confium but aren't eligible for registry publishing.

## ABI stability

Confium's plugin contract is the C ABI. Breaking changes require a **major version bump of `cfmp_interface_version`** — currently 0, will become 1 at first stable release.

The `cfmp_<iface>_*` per-interface versions are independent of `cfmp_interface_version`. A new cipher version (v1) doesn't bump the plugin contract version (still 0). But changing `cfmp_query_interfaces`'s wire format WOULD bump `cfmp_interface_version`.

## Plugin lifecycle

```
load lib
  → cfmp_interface_version → expect 0
  → cfmp_initialize(cfm, opts)
  → cfmp_query_interfaces → enumerate
  → cfmp_query_dependencies → resolve, fail if unmet
  → for each interface:
      look up cfmp_<iface>_<op> symbols
      build interface vtable
  → ready

unload
  → cfmp_finalize(cfm)
  → unload lib
```

`cfm_plugin_unload` (currently `unimplemented!()`) needs to land for graceful shutdown — see TODO #03's follow-up.

## Sandboxing (future)

Long-term, plugins should run in a sandbox (WASM, or a separate process with seccomp/AppSandbox). The contract should be designed so this is possible:

- Plugins never get raw `*mut Confium` — they get a handle to a controlled RPC-like surface.
- All I/O (file, network, key access) goes through Confium-provided primitives.

For 1.0, plugins are in-process and trusted. Sandboxing is a 2.0 conversation. See `TODO.roadmap/08-security-model.md`.

## Reference

- `TODO.finalize/02-plugin-interface-registry.md` — the discovery mechanism
- `TODO.roadmap/06-module-registry.md` — how plugins are distributed
