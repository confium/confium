# 06 — Module Registry

## What it is

A static-site-served catalog of Confium plugins, hosted at `registry.confium.org` (GitHub Pages). The catalog is the canonical source for plugin discovery, version resolution, integrity verification, and dependency graph analysis.

Not a server-side application. Just files served by GitHub Pages. Updates happen via PRs to the `confium/registry` repository.

## Why static

- **Auditable** — the entire catalog is a git repo. Every change is reviewable, every takedown is revertable.
- **Cheap** — GitHub Pages is free, globally CDN'd.
- **Trust-by-default** — no service to compromise. The trust root is the git history and the signatures on plugin artifacts, not a running server.
- **Mirrors trivially** — anyone can fork the static site and host their own mirror.
- **Matches precedent** — crates.io index is a git repo; npm registry is JSON files; Flatpak is static.

## URL structure

```
https://registry.confium.org/
├── index.toml                          # master catalog
├── plugins/
│   ├── botan/
│   │   ├── index.toml                  # all versions of botan plugin
│   │   ├── 3.2.0/
│   │   │   ├── manifest.toml           # metadata, dependencies, signatures
│   │   │   ├── artifact.sha256         # content hash
│   │   │   └── sigs/
│   │   │       ├── ribose.asc          # detached signature from Ribose
│   │   │       └── ni4.asc             # detached signature from maintainer @ni4
│   │   └── 3.3.0/
│   │       └── ...
│   ├── openssl/
│   │   └── ...
│   └── frost-ed25519/
│       └── ...
├── publishers/
│   ├── ribose.asc                      # publisher's long-term public key
│   └── ...
└── trust-roots.toml                    # default trust roots (multi-sig policy)
```

## `index.toml` schema

Master catalog of every published plugin name, latest version, and where to find details:

```toml
[[plugin]]
name = "botan"
latest = "3.2.0"
description = "Botan crypto provider plugin"
publishers = ["ribose", "ni4"]
versions-url = "/plugins/botan/index.toml"

[[plugin]]
name = "frost-ed25519"
latest = "0.4.1"
description = "FROST threshold signature for ed25519"
publishers = ["cfrg-frost-implementers"]
versions-url = "/plugins/frost-ed25519/index.toml"
```

## Per-plugin `manifest.toml`

One file per published version. Includes the FFI contract version, dependencies, supported algorithms, and a content hash:

```toml
[plugin]
name = "botan"
version = "3.2.0"
publisher = "ribose"
license = "BSD-2-Clause"
homepage = "https://botan.randombit.net"
source = "https://github.com/confium/confium-botan/tree/v3.2.0"

[confium]
contract-version = 0                   # cfmp_interface_version
min-runtime = "0.3.0"                  # minimum Confium runtime version

[dependencies]                         # other plugins that must be loaded
openssl = ">=1.1,<2.0"                 # NOT actually needed by botan, just an example

[interfaces]                           # which Confium interfaces this plugin implements
hash = 0                               # interface name + version
rng = 0
cipher = 0
aead = 0

[algorithms]                           # algorithms supported per interface
hash = ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"]
cipher = ["AES-128", "AES-256", "ChaCha20"]
aead = ["AES-256-GCM", "ChaCha20-Poly1305"]

[artifact]
url = "https://github.com/confium/confium-botan/releases/download/v3.2.0/libcfm-botan-3.2.0.dylib"
size = 1234567
sha256 = "abcd..."
mirrors = [
    "https://mirror.example.com/confium/botan/3.2.0/libcfm-botan-3.2.0.dylib",
]
```

## Trust model

- **Publisher identity** = PGP key registered in `publishers/`. Each publisher's pubkey is in `publishers/<name>.asc`.
- **Artifact signature** = detached PGP signature in `sigs/`. Multiple sigs allowed (multi-publisher endorsement).
- **Default trust roots** = `trust-roots.toml` lists publisher keys the official registry vouches for. End users can override.
- **Install policy** = at least one signature from a trusted publisher (or a user-accepted publisher). Otherwise, refuse with `Error::UntrustedPlugin`.

## CLI commands

```sh
confium search hash                    # list plugins offering "hash" interface
confium install botan@3.2.0            # install specific version
confium install botan                  # install latest
confium update                         # update all installed plugins
confium list                           # show installed plugins
confium remove botan
confium trust add ribose               # add a publisher to local trust store
confium info botan@3.2.0               # show manifest + signature details
confium publish ./build/               # upload to registry (opens a PR on the registry repo)
```

## Publishing flow

1. Plugin author builds artifact (`cargo build --release` → `.dylib/.so/.dll`).
2. Runs `confium publish ./build/`:
   - Computes SHA-256 of artifact.
   - Generates `manifest.toml` by querying the plugin via `cfmp_metadata`.
   - Asks which publisher key to sign with (looks up `~/.config/confium/publishers/*.asc`).
   - Signs the artifact, produces detached `.asc`.
   - Forks `github.com/confium/registry` (or pushes to a branch).
   - Opens a PR adding `plugins/<name>/<version>/` files.
3. Registry reviewers check the PR:
   - Publisher identity matches a known key.
   - Manifest matches the artifact.
   - At least one reviewer on the registry repo signs off.
4. PR merged → GitHub Pages deploys → plugin becomes globally available.

No server, no API, no rate limits. Just git + GitHub Pages.

## Mirroring

Anyone can mirror by:
1. Cloning `confium/registry`.
2. Adding mirror URLs to `manifest.toml`'s `artifact.mirrors`.
3. Hosting via their own GitHub Pages / S3 / CDN.

The `confium install` command tries the primary URL first, then mirrors. This protects against the registry being unavailable.

## Versioning and takedowns

- **Versions are immutable.** Once `plugins/botan/3.2.0/` is published, its content hash never changes. The directory is never edited, only deleted via a takedown.
- **Takedowns** = PRs that remove a version directory with a takedown reason in the PR description. Audit trail preserved in git history. Mirrors that already have the artifact are out of our control — but the trust signature remains valid; users can choose to keep or remove locally.
- **Latest pointer** = the `latest = "X"` field in the per-plugin `index.toml` is the only mutable field. Takedown PRs update it.

## Out of scope

- **No build farm.** The registry doesn't build plugins. Authors build locally and upload artifacts (probably via GitHub Releases of their plugin's repo, then linked in the manifest).
- **No automatic dependency resolution across plugins.** That's the CLI's job.
- **No telemetry.** Install counts, etc. — out of scope for the static site.

## Status

- Not started.
- Depends on: `confium-registry` client crate, `confium-publish` tool, `confium-cli` install command.
- Estimated effort: medium. Static-site generator + client CLI is roughly a week of focused work; signing ceremony and publisher onboarding is the harder part.

## Reference

- `TODO.roadmap/03-plugin-contract.md` — what the manifest describes
- `TODO.roadmap/07-cli-tools.md` — the install/publish commands
- `TODO.roadmap/08-security-model.md` — the trust model
