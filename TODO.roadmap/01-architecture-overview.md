# 01 — Architecture Overview

## The three pillars

Confium is built around three separable pillars. Each is independently deployable, versioned, and replaceable.

```
┌─────────────────────────────────────────────────────────────┐
│                       Application                            │
│              (Thunderbird / RNP / etc.)                      │
└─────────────────────────────────────────────────────────────┘
                              │
                       Confium FFI (C ABI)
                              │
┌─────────────────────────────────────────────────────────────┐
│                     Confium Core                             │
│  ┌─────────────────┐  ┌──────────────────┐                  │
│  │   Engine        │  │      Store       │                  │
│  │  (execution)    │  │   (persistence)  │                  │
│  └─────────────────┘  └──────────────────┘                  │
│  ┌─────────────────┐  ┌──────────────────┐                  │
│  │   Registry      │  │    Network       │                  │
│  │  (plugin mgmt)  │  │   (transport)    │                  │
│  └─────────────────┘  └──────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
                              │
            Confium Plugin Contract (FFI per interface)
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   Provider plugins       Store plugins         (someday)
   (Botan, OpenSSL,       (filesystem,          Net plugins
    mbtls, custom TC)     smartcard, HSM,       (transport impls)
                          cloud)
```

## Pillar 1 — Engine (crypto execution)

The Engine loads provider plugins, exposes a uniform API for each cryptographic primitive class (hash, cipher, AEAD, KDF, RNG, signature, KEM, keyfmt, **threshold signature, threshold KEM**), and dispatches per-call to whichever plugin is installed.

Per-primitive interfaces (each is its own `cfmp_<iface>_` wire prefix):

| Interface | Status | Notes |
|---|---|---|
| `hash` | shipped | `cfmp_hash_*` |
| `rng` | shipped (0.3) | `cfmp_rng_*` |
| `symmetric` (cipher) | shipped (0.3) | `cfmp_cipher_*` |
| `aead` | shipped (0.3) | `cfmp_aead_*` |
| `kdf` | shipped (0.3) | `cfmp_kdf_*` |
| `signature` | TODO #09 | incl. PQC composite |
| `kem` | TODO #10 | incl. PQC composite |
| `keyfmt` | TODO #11 | RFC 9580 packets, PKCS#8, JWK, raw |
| `tc-signature` | roadmap | rounds, shares, propose/combine |
| `tc-kem` | roadmap | distributed key generation |
| `tc-dkg` | roadmap | distributed key generation standalone |

## Pillar 2 — Store (key/secret persistence)

The Store manages compartmentalized key material. Two compartments per `(module_id, app_id)` pair:

- **Public** — distributed, identity-indexed, signed. Anyone can read; writes are gated by an identity-signature scheme.
- **Private** — per-device, key-id-indexed, optionally hardware-backed (smartcard / HSM / TPM / cloud KMS).

The Store API is one FFI (`cfmp_keystore_*`). Backends are pluggable:
- `filesystem` — RFC 9580 packet files, default
- `memory` — in-process (test/dev)
- `pkcs11` — HSM/smartcard
- `tpm` — TPM 2.0
- `cloud-kms` — AWS KMS / GCP KMS / Azure KV

## Pillar 3 — Registry (plugin discovery)

A static-site-served index of plugins. Each plugin entry has:
- Identity (name, version, vendor)
- Manifest declaring FFI contract versions, supported algorithms, dependencies on other plugins
- Download URLs (multiple mirrors)
- Detached signature(s) from one or more trusted publishers

The CLI (`confium install <name>@<version>`) fetches the index, verifies signatures against a configured trust root, downloads the artifact, and stages it for the Engine to load.

The static site is served from `registry.confium.org` via GitHub Pages. See `TODO.roadmap/06-module-registry.md`.

## Pillar 4 — Network (multi-party transport)

Threshold cryptography requires multiple parties to talk to each other during distributed signing / decryption / key generation. Confium supplies a Network abstraction so plugin authors don't have to roll their own:

- `in-process` — for tests and single-node simulators
- `tcp` / `quic` — for production LAN deployment
- `websocket` / `http` — for cloud / WAN deployment
- `mock` — for deterministic CI vectors

The TC plugin requests a transport by name (`cfm_net_connect("quic://node1.example.com:443")`), and Confium routes bytes for it. See `TODO.roadmap/05-networking-primitives.md`.

## How the pillars compose

A 2-of-3 threshold RSA signature session looks like:

1. **Store** → load the local key share (private compartment)
2. **Network** → connect to peer parties `alice@example.com:443`, `bob@example.com:443`
3. **Engine:tc-signature** → invoke the threshold-RSA plugin's `round_1` on each party
4. **Network** → exchange round-1 messages
5. **Engine:tc-signature** → invoke `round_2`, etc.
6. **Engine:signature** → emit final signature in standard RSA format

None of the pillars know about each other directly — they communicate through the Engine's session state. This is the MECE property: each pillar does exactly one thing.

## Anti-goals

- Confium does not implement algorithms. Plugin authors do.
- Confium does not pick winners among competing schemes. The registry is content-neutral; trust is established by publisher signatures, not by Confium.
- Confium does not require online access. The Registry index can be cached; plugins can be installed offline from local files.
- Confium does not embed policy. Algorithm preferences, key-id namespaces, and trust roots are user-controlled.

## Reference

- `TODO.roadmap/02-workspace-layout.md` — how the pillars map to Rust crates
- `TODO.finalize/02-plugin-interface-registry.md` — the registry pattern that powers the Engine
