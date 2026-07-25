---
layout: default
title: Confium Plugin Registry
---

# Confium Plugin Registry

Welcome to the official static catalog of Confium plugins, hosted at
`registry.confium.org`. This site lists every plugin the project vouches
for, along with the manifests, publisher keys, and trust roots needed to
install and verify them.

The registry is **just files** — no server, no API, no rate limits. Updates
happen through pull requests merged to this repository; GitHub Pages
deploys them globally within minutes.

## Install a plugin

```sh
confium install botan            # latest version
confium install botan@3.2.0      # specific version
confium search hash              # list plugins implementing the "hash" interface
confium list                     # show installed plugins
confium info botan@3.2.0         # show manifest + signature details
```

See [Installing a plugin](docs/installing.md) for the full workflow,
including how trust is verified before anything is loaded.

## Publish a plugin

1. Build your plugin artifact.
2. Generate `manifest.toml` (the `confium-publish` tool helps).
3. Sign the artifact with your publisher key.
4. Open a PR adding `plugins/<name>/<version>/`.

See [Publishing a plugin](docs/publishing.md) and
[Publisher onboarding](docs/publisher-onboarding.md).

## How trust works

Every plugin artifact must carry at least one detached PGP signature from a
publisher whose public key is listed under
[`publishers/`](publishers/) and whose identity is anchored in
[`trust-roots.toml`](trust-roots.toml). The install command refuses to load
any plugin that fails this check. See [Trust model](docs/trust-model.md).

## Browse

- [Master catalog (`index.toml`)](index.toml)
- [Example plugin: botan 3.2.0 manifest](plugins/botan/3.2.0/manifest.toml)
- [Publishers](publishers/)
- [Trust roots](trust-roots.toml)

## Status

Scaffolding. The example `botan` entry is placeholder content — the
artifact URL, hash, and signature are illustrative only.
