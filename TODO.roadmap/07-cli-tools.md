# 07 — CLI Tools

## Three commands

| Command | Crate | Purpose |
|---|---|---|
| `confium` | `crates/confium-cli` | End-user: install, list, remove, configure |
| `confium-publish` | `crates/confium-publish` | Plugin author: build + sign + publish |
| `confiumd` | `crates/confium-cli` (sub-binary) | Long-running daemon (optional, for app integration) |

## `confium` — end-user command

```
confium --help

Confium trust store framework

USAGE:
    confium <COMMAND>

COMMANDS:
    install <plugin>[@version]     Install a plugin from the registry
    remove <plugin>                Uninstall a plugin
    update [<plugin>]              Update plugin(s) to latest
    list                           List installed plugins
    info <plugin>[@version]        Show plugin manifest details
    search [<interface>] [<algo>]  Search the registry index
    trust                          Manage publisher trust roots
    untrust                        Revoke a publisher
    config                         Edit local config
    version                        Show version and crate info
```

### Examples

```sh
# Install latest Botan
confium install botan

# Install specific version
confium install botan@3.2.0

# Install a threshold signature plugin (auto-installs dependencies)
confium install frost-ed25519

# Search by interface
confium search aead                  # all plugins that implement aead
confium search hash SHA-256          # all plugins that implement SHA-256 hash

# Trust a publisher (adds their pubkey to local store)
confium trust add ribose --key E73B...B13F
confium trust list

# Show what's installed
confium list
# NAME          VERSION  VENDOR    INTERFACES               ALGORITHMS
# botan         3.2.0    ribose    hash,rng,cipher,aead     SHA-256,AES-256,...
# openssl       1.1.1    ribose    hash,rng,cipher,aead     SHA-256,AES-128,...
# frost-ed25519 0.4.1    cfrg      tc-signature             FROST-ed25519
```

## `confium-publish` — author command

```sh
confium-publish ./target/release/libcfm-botan.dylib \
    --name botan \
    --version 3.2.0 \
    --publisher ribose \
    --signing-key ~/.config/confium/publishers/ribose.asc \
    --registry git@github.com:confium/registry.git \
    --artifact-base https://github.com/confium/confium-botan/releases/download/v3.2.0/
```

What it does:
1. Loads the plugin via the FFI contract.
2. Calls `cfmp_metadata` to get name/version/vendor/etc.
3. Calls `cfmp_query_interfaces` to enumerate interfaces.
4. Computes SHA-256 of the artifact.
5. Generates `manifest.toml`.
6. Generates a detached PGP signature of the artifact + manifest.
7. Clones the registry, adds `plugins/<name>/<version>/` files, commits, opens a PR.

## `confiumd` — daemon (optional)

For applications that want a persistent Confium service (instead of loading the cdylib directly):

```sh
confiumd --listen unix:///tmp/confium.sock
```

Applications connect via Unix socket and speak a length-prefixed JSON-RPC protocol. Useful for:
- Browser extensions (via a native-messaging bridge)
- Long-running servers that want centralized plugin state
- Sandboxed plugin execution (separate process per plugin)

Status: 2.0+, not for 1.0.

## Configuration

```toml
# ~/.config/confium/config.toml

[registry]
default = "https://registry.confium.org"
mirrors = [
    "https://confium-registry-mirror.example.com",
]

[trust]
# Default publisher keys (also fetched from registry's trust-roots.toml)
publishers = [
    "ribose",
    "cfrg-frost-implementers",
]

[plugins]
# Where to install plugins
install-dir = "~/.local/share/confium/plugins/"

[engine]
# Which plugins to auto-load on Confium init
auto-load = ["botan", "openssl"]

[preferred]
# Per-interface provider preferences (highest first)
hash = ["botan", "openssl"]
rng = ["botan"]
cipher = ["botan", "openssl"]
aead = ["botan", "openssl"]
```

## Implementation notes

- `confium-cli` is a thin wrapper over `confium-core` (loader), `confium-registry` (client), `confium-store` (local config).
- `clap` for argument parsing (popular, BSD-3-Clause, in our license allowlist).
- `indicatif` for progress bars during install (also license-compatible).
- Sub-commands are in separate files (`commands/install.rs`, `commands/remove.rs`, etc.) — easy to add new ones without touching existing.

## Distribution

- Static binaries for Linux, macOS, Windows (via `cargo-dist` or similar).
- Homebrew tap for macOS (`brew install confium`).
- APT/YUM repositories for Linux (built via `cargo-dist`).
- winget / Chocolatey for Windows.
- Nix flake already exists in the repo.

## Anti-goals

- No GUI. The CLI is the user interface; GUIs are separate projects.
- No scripting language built in. Use the CLI from bash, or the Rust API from Rust, or the Ruby bindings for Ruby.
- No "Confium Cloud." Confium is local-first.

## Status

- Not started.
- Depends on: `confium-registry` (for install/publish), `confium-core` (for load/list).

## Reference

- `TODO.roadmap/06-module-registry.md` — what install/publish talk to
- `TODO.roadmap/02-workspace-layout.md` — crate layout
