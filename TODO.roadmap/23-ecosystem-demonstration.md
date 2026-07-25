# 23 — Ecosystem demonstration

## Why

The 23-crate workspace is real code with 555+ tests, but there's no
end-user-visible artifact that proves it works. Stakeholders (NIST
evaluators, potential plugin authors, Ribose management, Mozilla) need
to SEE the system working, not read a diff stat.

## Goal

Ship runnable demo programs under `examples/` that each exercise one
pillar of the ecosystem end-to-end. Each demo is a standalone binary
invocable via `cargo run --example <name>`.

## Demos (priority order)

### 1. `threshold-signing` (THE killer demo)

3-party FROST-ed25519 signing session via the in-process transport.
Output: a valid ed25519 signature that verifies under `openssl` or
standard tools. Prints the session transcript (round messages, timing).

```sh
cargo run --example threshold-signing
# DKG: 3 parties generate distributed key shares...
# Signing: 2-of-3 threshold session for message "hello world"...
# Signature: <hex>
# Verifying with ed25519-dalek... VALID
# Session completed in 12ms, exchanged 2,148 bytes.
```

### 2. `plugin-load-and-hash`

Load the mock hash plugin via the standard Confium loader, hash a
message, print the digest. Demonstrates: plugin contract, registry
pattern, hash interface, FFI lifecycle.

```sh
cargo run --example plugin-load-and-hash
# Loaded plugin: mock-hash v0.1.0
# Algorithm: XOR-256
# Hash of "hello world": <hex>
```

### 3. `keystore-roundtrip`

Create a keystore (memory backend), put a secret, get it back, enumerate.
Demonstrates: Store pillar, compartmentalization, backend trait.

### 4. `network-roundtrip`

In-process transport: two endpoints exchange messages. Demonstrates:
Network pillar, transport abstraction, message framing.

### 5. `registry-search-and-install`

Point at the local static-site registry, search for plugins, install
one. Demonstrates: Registry pillar, manifest parsing, trust model.

### 6. `audit-log-stream`

Run any operation and watch audit events stream to stdout as JSONL.
Demonstrates: security model, observability.

### 7. `sandbox-wasm-demo`

Load a WASM module in the sandbox, call a function, show capability
gating (denied call → sentinel, granted call → success).

### 8. `nist-bench`

Run the NIST evaluation harness against the FROST scheme with the
sample vector. Print pass/fail + timing report.

## Implementation

Each demo lives at `examples/<name>.rs`. Root Cargo.toml gains an
`[[example]]` section per demo. Demos link against `confium-core` (for
crypto), `confium-tc` (for threshold), `confium-store` (for keystore),
`confium-net` (for networking), `confium-registry` (for registry).

## Out of scope

- Browser-based demos (needs confiumd + WebSocket transport, separate)
- Mobile demos (not yet targeted)
- Production-grade CLI polish (demos are for demonstration, not daily use)
