---
layout: default
title: Publishing a plugin
---

# Publishing a plugin

Publishing is PR-driven. There is no upload API, no server, no build farm.
You build the artifact locally, sign it, and open a pull request against
this repository; reviewers merge it; GitHub Pages deploys it globally.

## Prerequisites

- A publisher identity. If you do not have one yet, follow
  [Publisher onboarding](publisher-onboarding.md) first.
- The Confium plugin SDK (`confium-api`) and the `confium-publish` tool.
- A local copy of this repository (or a fork of it).

## 1. Build the artifact

Build your plugin as a dynamic library:

```sh
cargo build --release
```

This produces a `.dylib` (macOS), `.so` (Linux), or `.dll` (Windows) under
`target/release/`. For a cross-platform release you will typically publish
one artifact per target triple; this guide covers the single-artifact case.

## 2. Generate the manifest

Use `confium-publish` to introspect the freshly built plugin and emit a
`manifest.toml` matching the schema in
[`TODO.roadmap/06-module-registry.md`](https://github.com/confium/confium/blob/main/TODO.roadmap/06-module-registry.md):

```sh
confium-publish manifest ./target/release/libcfm-botan-3.2.0.dylib
```

The tool queries the plugin via `cfmp_metadata` to populate the
`[interfaces]` and `[algorithms]` sections, computes the SHA-256 for the
`[artifact]` section, and writes the file to stdout. Redirect it into your
plugin directory:

```sh
confium-publish manifest ./target/release/libcfm-botan-3.2.0.dylib \
  > plugins/botan/3.2.0/manifest.toml
```

You will still need to edit the `[plugin]`, `[confium]`, and `[dependencies]`
sections by hand — the tool cannot guess those.

## 3. Upload the artifact

Upload the `.dylib`/`.so`/`.dll` to a GitHub Release on your plugin's own
repository, then set `artifact.url` in `manifest.toml` to the release
download URL. The registry does not host binary artifacts; it only links to
them. Add any mirror URLs to `artifact.mirrors`.

## 4. Sign the artifact

Sign the artifact with your publisher key:

```sh
gpg --local-user <your-publisher-key-id> \
    --detach-sign --armor \
    --output plugins/botan/3.2.0/sigs/<your-publisher-name>.asc \
    ./target/release/libcfm-botan-3.2.0.dylib
```

Place the detached signature under `plugins/<name>/<version>/sigs/`. If
another publisher endorses the same artifact, they add their own signature
file in the same directory.

## 5. Open the PR

Add three things to your PR:

1. The version directory `plugins/<name>/<version>/` containing
   `manifest.toml`, `artifact.sha256`, and `sigs/<publisher>.asc`.
2. A `[[version]]` entry in `plugins/<name>/index.toml` (or create the file
   if this is the first version of the plugin).
3. A `[[plugin]]` entry in the top-level `index.toml` if this is a new
   plugin name.

In the PR description, include:

- The artifact URL and its SHA-256 (so reviewers can fetch and verify).
- The publisher key fingerprint you signed with.
- A pointer to the out-of-band verification of your publisher identity, if
  this is your first publish.

## 6. Review and merge

Registry reviewers check:

- The publisher identity matches a key in `publishers/` that is anchored in
  `trust-roots.toml`.
- The detached signature verifies against the publisher key and the
  artifact referenced by `manifest.toml`.
- The manifest fields match what the plugin reports via `cfmp_metadata`.
- The artifact hash in `manifest.toml` matches `artifact.sha256`.

Once merged, GitHub Pages republishes the site within minutes and the
plugin becomes globally installable.

See [Installing a plugin](installing.md) for the consumer side, and
[Trust model](trust-model.md) for why signatures matter.
