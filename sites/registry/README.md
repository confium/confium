# Confium Plugin Registry

This is the static-site catalog of Confium plugins, served via GitHub Pages
at `registry.confium.org` (domain pending DNS configuration; until then the
site is reachable at the `*.github.io` Pages URL).

The registry is **just files**. There is no server-side application, no API,
and no database. Discovery, version resolution, integrity verification, and
the trust graph all read from TOML and markdown files committed to git and
published by GitHub Pages on every merge to `main`.

## Why static

- **Auditable** — the entire catalog is a git repo. Every change is
  reviewable, every takedown is revertable.
- **Cheap** — GitHub Pages is free and globally CDN'd.
- **Trust-by-default** — no service to compromise. The trust root is the git
  history and the PGP signatures on plugin artifacts, not a running server.
- **Mirrors trivially** — anyone can fork this directory and host their own
  mirror.

This mirrors the precedent set by crates.io's git index, npm's JSON files,
and Flatpak's static manifests.

## Layout

```
sites/registry/
├── index.toml                 # master catalog (one [[plugin]] per published name)
├── index.md                   # landing page rendered by GitHub Pages
├── plugins/
│   └── <name>/
│       ├── index.toml         # all published versions of this plugin
│       └── <version>/
│           ├── manifest.toml  # metadata, dependencies, interfaces, algorithms
│           ├── artifact.sha256
│           └── sigs/          # detached PGP signatures (one per endorsing publisher)
├── publishers/
│   └── <name>.asc             # long-term publisher public key
├── trust-roots.toml           # default trust roots (multi-sig policy)
└── docs/                      # publishing, installing, trust model docs
```

See [`TODO.roadmap/06-module-registry.md`](../../TODO.roadmap/06-module-registry.md)
in the main repository for the full design.

## Adding a plugin

Plugin publishing is PR-driven. There is no upload API.

1. Build your plugin artifact locally (`cargo build --release`).
2. Generate `manifest.toml` (the `confium-publish` tool helps; see
   [`docs/publishing.md`](docs/publishing.md)).
3. Sign the artifact with your publisher key and place the detached
   signature in `plugins/<name>/<version>/sigs/`.
4. Open a PR against this repo adding the plugin's directory and a
   `[[plugin]]` entry to `index.toml`.

Registry reviewers verify publisher identity, manifest accuracy, and at
least one trusted signature before merging. On merge, GitHub Pages deploys
the update globally within minutes.

See:
- [Publishing a plugin](docs/publishing.md)
- [Installing a plugin](docs/installing.md)
- [Trust model](docs/trust-model.md)
- [Publisher onboarding](docs/publisher-onboarding.md)

## Status

Scaffolding. The example `botan` entry is placeholder content — the
artifact URL, hash, and signature are illustrative only. Real plugins will
replace these once the `confium-publish` tool and signing ceremony land.

## License

Catalog content (manifests, docs, publisher keys) is published under the
same license as the main Confium repository. See
[`LICENSE.md`](../../LICENSE.md).
