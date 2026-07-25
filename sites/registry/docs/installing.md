---
layout: default
title: Installing a plugin
---

# Installing a plugin

Confium installs plugins by reading this registry, fetching the referenced
artifact, verifying at least one trusted publisher signature, and placing
the artifact in the local plugin directory.

## Prerequisites

- The `confium` CLI installed (see the main repository README).
- A working network connection to `registry.confium.org` (or a configured
  mirror).

## Install a specific version

```sh
confium install botan@3.2.0
```

This reads [`/plugins/botan/3.2.0/manifest.toml`](../plugins/botan/3.2.0/manifest.toml),
downloads the artifact from `artifact.url` (falling back to entries in
`artifact.mirrors`), verifies its SHA-256 against `artifact.sha256`, then
verifies at least one signature in
[`/plugins/botan/3.2.0/sigs/`](../plugins/botan/3.2.0/sigs/) against a
publisher anchored in [`trust-roots.toml`](../trust-roots.toml).

## Install the latest version

```sh
confium install botan
```

This reads [`/plugins/botan/index.toml`](../plugins/botan/index.toml) to
resolve the `latest` pointer, then proceeds as above.

## Discover plugins

```sh
confium search hash          # list plugins implementing the "hash" interface
confium search aead          # list plugins implementing the "aead" interface
confium list                 # show installed plugins
confium info botan@3.2.0     # show manifest + signature details
```

## Update installed plugins

```sh
confium update               # update all installed plugins to their latest
```

## Remove a plugin

```sh
confium remove botan
```

## Trust

If an artifact has no signature from a publisher in your trust store, the
install is refused with `Error::UntrustedPlugin`. To accept a new
publisher:

```sh
confium trust add ribose     # add a publisher to your local trust store
```

See [Trust model](trust-model.md) for the full model and how to override
the defaults.
