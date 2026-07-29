# 02 — Workspace Layout

## Why a workspace

Confium is not one crate. It's four pillars (Engine, Store, Registry, Network) plus shared infrastructure (FFI types, error model, plugin contract) plus per-pillar plugin SDKs. Splitting into workspace crates:

- Gives plugin authors a small, stable crate to depend on (`confium-api`) without pulling in the entire Engine.
- Lets the CLI, the test harness, and the daemon be separate binaries that share library code.
- Trims compile times — touching the Engine doesn't rebuild the Registry client.
- Matches idiomatic Rust monorepo layout (cf. parsanol-rs, ribose's other Rust projects).

## Proposed layout

```
confium/
├── Cargo.toml                          # workspace manifest
├── crates/
│   ├── confium-api/                    # the public Rust API + plugin SDK
│   │   └── ...
│   ├── confium-core/                   # Engine: plugin loader, registry, dispatch
│   │   └── ...                         # (current src/lib.rs, src/hash.rs, etc. move here)
│   ├── confium-store/                  # Store pillar: API + filesystem/memory backends
│   ├── confium-store-pkcs11/           # PKCS#11 backend (optional crate)
│   ├── confium-store-tpm/              # TPM 2.0 backend (optional crate)
│   ├── confium-store-cloud/            # AWS/GCP/Azure KMS backends (optional crate)
│   ├── confium-registry/               # Registry client + signing/verification
│   ├── confium-net/                    # Network abstraction + transports
│   ├── confium-net-tcp/                # TCP transport
│   ├── confium-net-quic/               # QUIC transport
│   ├── confium-net-ws/                 # WebSocket transport
│   ├── confium-tc/                     # Threshold-cryptography primitives + plugin SDK
│   ├── confium-cli/                    # `confium` command-line tool
│   ├── confium-publish/                # `confium-publish` tool for registry uploads
│   ├── confium-ffi/                    # the cdylib: re-exports api with #[no_mangle]
│   ├── confium-macros/                 # proc-macros: #[plugin_interface], etc.
│   └── confium-test-harness/           # mock plugins, fuzzing harness, NIST vectors
├── plugins/                            # in-repo mock/example plugins
│   ├── mock-hash/                      # deterministic hash for tests
│   ├── mock-cipher/                    # XOR cipher for tests
│   └── mock-rng/                       # seeded RNG for deterministic tests
├── sites/
│   └── registry/                       # GitHub Pages site (see #06)
├── docs/                               # architecture, plugin-author guide
├── cpp-tests/                          # existing C++ binding tests
├── TODO.finalize/                      # tactical coding tasks
└── TODO.roadmap/                       # this directory
```

## Crate dependency rules

Strict layering, no cycles:

- `confium-api` is the bottom. Everyone can depend on it. It exports the trait shapes, the FFI types, the error model. It does **not** include the plugin loader.
- `confium-core` depends on `confium-api`, implements the loader.
- `confium-store` depends on `confium-api`.
- `confium-registry` depends on `confium-api`, `confium-store` (for verifying install destinations).
- `confium-net` depends on `confium-api`.
- `confium-tc` depends on `confium-api`, `confium-net`, `confium-store` (TC needs both networking and storage for share material).
- `confium-ffi` depends on `confium-core`, `confium-store`, `confium-registry`, `confium-net`, `confium-tc`. It re-exports their public APIs behind `#[no_mangle] pub extern "C"` wrappers.
- `confium-cli` depends on `confium-core`, `confium-registry`, `confium-store`.
- `confium-macros` is a proc-macro crate, no deps on the above.

The workspace Cargo.toml uses `[workspace.dependencies]` to share versions:

```toml
[workspace.dependencies]
confium-api = { path = "crates/confium-api" }
libloading = "0.8"
snafu = "0.8"
inventory = "0.3"
zeroize = "1.8"
```

## Stability tiers

Each crate carries a `publish = [...]` flag in its package metadata indicating the stability tier:

- **stable** — public API can be relied on; breaking changes require major version bump
- **beta** — public API expected to stabilize but may change between minor versions
- **alpha** — experimental; API may break at any time
- **internal** — published because external plugins may need it, but no stability guarantee

Today (0.x) most crates are alpha. As we hit 1.0, `confium-api` and `confium-ffi` should become stable; everything else can stay alpha/beta.

## Migration from current single-crate layout

1. Create workspace `Cargo.toml` at repo root.
2. Move current `Cargo.toml` + `src/` to `crates/confium-core/`.
3. Split `ffi/` module: FFI types that plugin authors need go to `crates/confium-api/`; the `#[no_mangle] extern "C"` entry points stay in `confium-core` (they'll be re-exported by `confium-ffi` later).
4. Create empty crate skeletons for all other crates.
5. Update CI (`ci.yml`) to use `cargo test --workspace` and `cargo clippy --workspace`.

This is a single PR that doesn't change behavior — just moves files. After it lands, the pillar-specific work can be parallelized.

## Reference

- `TODO.roadmap/01-architecture-overview.md` — pillar design
- `TODO.finalize/02-plugin-interface-registry.md` — registry pattern (lives in `confium-core`)
